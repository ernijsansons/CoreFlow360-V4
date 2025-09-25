/**
 * Payment Terms and Aging Manager
 * Handles payment terms calculation and accounts receivable aging
 */

import type { D1Database } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';
import {
  PaymentTerms,
  PaymentTermType,
  Invoice,
  InvoiceStatus,
  AgingReport,
  InvoicePayment,
  Customer
} from './types';
import { validateBusinessId, roundToCurrency } from './utils';
import { CurrencyManager } from './currency-manager';

export interface AgingBucket {
  current: number;
  days1to30: number;
  days31to60: number;
  days61to90: number;
  over90Days: number;
}

export interface CustomerAgingDetail {
  customerId: string;
  customerName: string;
  invoices: Array<{
    invoiceId: string;
    invoiceNumber: string;
    issueDate: number;
    dueDate: number;
    daysPastDue: number;
    balanceDue: number;
    agingBucket: 'current' | '1-30' | '31-60' | '61-90' | '90+';
  }>;
  totals: AgingBucket & { total: number };
}

export // TODO: Consider splitting PaymentTermsManager into smaller, focused classes
class PaymentTermsManager {
  private logger: Logger;
  private db?: D1Database;
  private currencyManager?: CurrencyManager;

  constructor(db?: D1Database, currencyManager?: CurrencyManager) {
    this.logger = new Logger();
    this.db = db;
    this.currencyManager = currencyManager;
  }

  /**
   * Calculate due date based on payment terms
   */
  calculateDueDate(issueDate: number, terms: PaymentTerms): number {
    const issueDateTime = new Date(issueDate);

    switch (terms.type) {
      case PaymentTermType.DUE_ON_RECEIPT:
        return issueDate; // Due immediately

      case PaymentTermType.NET:
        if (!terms.netDays) {
          throw new Error('Net days must be specified for NET payment terms');
        }
        const netDate = new Date(issueDateTime);
        netDate.setDate(netDate.getDate() + terms.netDays);
        return netDate.getTime();

      case PaymentTermType.END_OF_MONTH:
        const eomDate = new Date(issueDateTime.getFullYear(), issueDateTime.getMonth() + 1, 0);
        if (terms.netDays) {
          eomDate.setDate(eomDate.getDate() + terms.netDays);
        }
        return eomDate.getTime();

      case PaymentTermType.CASH_ON_DELIVERY:
        return issueDate; // Due on delivery

      case PaymentTermType.CUSTOM:
        if (!terms.netDays) {
          return issueDate;
        }
        const customDate = new Date(issueDateTime);
        customDate.setDate(customDate.getDate() + terms.netDays);
        return customDate.getTime();

      default:
        return issueDate;
    }
  }

  /**
   * Calculate early payment discount
   */
  calculateEarlyPaymentDiscount(
    amount: number,
    paymentDate: number,
    issueDate: number,
    terms: PaymentTerms
  ): number {
    if (!terms.discountDays || !terms.discountPercentage) {
      return 0;
    }

    const daysSinceIssue = Math.floor((paymentDate - issueDate) / (1000 * 60 * 60 * 24));

    if (daysSinceIssue <= terms.discountDays) {
      return roundToCurrency(amount * (terms.discountPercentage / 100));
    }

    return 0;
  }

  /**
   * Generate aging report for all customers
   */
  async generateAgingReport(
    businessId: string,
    asOfDate?: number
  ): Promise<AgingReport[]> {
    if (!this.db) {
      throw new Error('Database not initialized');
    }

    const validBusinessId = validateBusinessId(businessId);
    const reportDate = asOfDate || Date.now();

    try {
      // Get base currency for business
      let baseCurrency = 'USD'; // fallback
      if (this.currencyManager) {
        baseCurrency = await this.currencyManager.getBaseCurrency(validBusinessId);
      }

      // Get all customers with outstanding invoices
      const result = await this.db.prepare(`
        SELECT
          c.id as customer_id,
          c.name as customer_name,
          i.id as invoice_id,
          i.invoice_number,
          i.issue_date,
          i.due_date,
          i.balance_due,
          i.currency
        FROM customers c
        INNER JOIN invoices i ON c.id = i.customer_id
        WHERE c.business_id = ?
        AND i.business_id = ?
        AND i.status IN ('SENT', 'VIEWED', 'PARTIALLY_PAID', 'OVERDUE')
        AND i.balance_due > 0
        ORDER BY c.name, i.due_date
      `).bind(validBusinessId, validBusinessId).all();

      const customerMap = new Map<string, CustomerAgingDetail>();

      for (const row of result.results || []) {
        const customerId = row.customer_id as string;
        const customerName = row.customer_name as string;
        const dueDate = row.due_date as number;
        const invoiceCurrency = row.currency as string;
        let balanceDue = row.balance_due as number;

        // Convert to base currency if different
        if (this.currencyManager && invoiceCurrency !== baseCurrency) {
          const conversion = await this.currencyManager.convertAmount(
            balanceDue,
            invoiceCurrency,
            baseCurrency,
            validBusinessId,
            reportDate
          );
          balanceDue = conversion.convertedAmount;
        }

        const daysPastDue = Math.max(0, Math.floor((reportDate - dueDate) / (1000 * 60 * 60 * 24)));
        const agingBucket = this.getAgingBucket(daysPastDue);

        if (!customerMap.has(customerId)) {
          customerMap.set(customerId, {
            customerId,
            customerName,
            invoices: [],
            totals: {
              current: 0,
              days1to30: 0,
              days31to60: 0,
              days61to90: 0,
              over90Days: 0,
              total: 0
            }
          });
        }

        const customerDetail = customerMap.get(customerId)!;

        customerDetail.invoices.push({
          invoiceId: row.invoice_id as string,
          invoiceNumber: row.invoice_number as string,
          issueDate: row.issue_date as number,
          dueDate,
          daysPastDue,
          balanceDue,
          agingBucket
        });

        // Add to appropriate aging bucket
        switch (agingBucket) {
          case 'current':
            customerDetail.totals.current += balanceDue;
            break;
          case '1-30':
            customerDetail.totals.days1to30 += balanceDue;
            break;
          case '31-60':
            customerDetail.totals.days31to60 += balanceDue;
            break;
          case '61-90':
            customerDetail.totals.days61to90 += balanceDue;
            break;
          case '90+':
            customerDetail.totals.over90Days += balanceDue;
            break;
        }

        customerDetail.totals.total += balanceDue;
      }

      // Convert to aging report format
      const agingReport: AgingReport[] = Array.from(customerMap.values()).map(detail => ({
        customerId: detail.customerId,
        customerName: detail.customerName,
        current: roundToCurrency(detail.totals.current),
        days1to30: roundToCurrency(detail.totals.days1to30),
        days31to60: roundToCurrency(detail.totals.days31to60),
        days61to90: roundToCurrency(detail.totals.days61to90),
        over90Days: roundToCurrency(detail.totals.over90Days),
        total: roundToCurrency(detail.totals.total),
        currency: baseCurrency
      }));

      this.logger.info('Aging report generated', {
        customerCount: agingReport.length,
        totalOutstanding: agingReport.reduce((sum, r) => sum + r.total, 0),
        businessId: validBusinessId
      });

      return agingReport;

    } catch (error) {
      this.logger.error('Failed to generate aging report', error, {
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Get detailed aging for specific customer
   */
  async getCustomerAgingDetail(
    customerId: string,
    businessId: string,
    asOfDate?: number
  ): Promise<CustomerAgingDetail | null> {
    if (!this.db) {
      throw new Error('Database not initialized');
    }

    const validBusinessId = validateBusinessId(businessId);
    const reportDate = asOfDate || Date.now();

    try {
      const customerResult = await this.db.prepare(`
        SELECT id, name FROM customers
        WHERE id = ? AND business_id = ?
      `).bind(customerId, validBusinessId).first();

      if (!customerResult) {
        return null;
      }

      const invoicesResult = await this.db.prepare(`
        SELECT
          id, invoice_number, issue_date, due_date, balance_due, currency
        FROM invoices
        WHERE customer_id = ?
        AND business_id = ?
        AND status IN ('SENT', 'VIEWED', 'PARTIALLY_PAID', 'OVERDUE')
        AND balance_due > 0
        ORDER BY due_date
      `).bind(customerId, validBusinessId).all();

      const detail: CustomerAgingDetail = {
        customerId,
        customerName: customerResult.name as string,
        invoices: [],
        totals: {
          current: 0,
          days1to30: 0,
          days31to60: 0,
          days61to90: 0,
          over90Days: 0,
          total: 0
        }
      };

      for (const row of invoicesResult.results || []) {
        const dueDate = row.due_date as number;
        const balanceDue = row.balance_due as number;
        const daysPastDue = Math.max(0, Math.floor((reportDate - dueDate) / (1000 * 60 * 60 * 24)));
        const agingBucket = this.getAgingBucket(daysPastDue);

        detail.invoices.push({
          invoiceId: row.id as string,
          invoiceNumber: row.invoice_number as string,
          issueDate: row.issue_date as number,
          dueDate,
          daysPastDue,
          balanceDue,
          agingBucket
        });

        // Add to appropriate aging bucket
        switch (agingBucket) {
          case 'current':
            detail.totals.current += balanceDue;
            break;
          case '1-30':
            detail.totals.days1to30 += balanceDue;
            break;
          case '31-60':
            detail.totals.days31to60 += balanceDue;
            break;
          case '61-90':
            detail.totals.days61to90 += balanceDue;
            break;
          case '90+':
            detail.totals.over90Days += balanceDue;
            break;
        }

        detail.totals.total += balanceDue;
      }

      // Round all totals
      detail.totals.current = roundToCurrency(detail.totals.current);
      detail.totals.days1to30 = roundToCurrency(detail.totals.days1to30);
      detail.totals.days31to60 = roundToCurrency(detail.totals.days31to60);
      detail.totals.days61to90 = roundToCurrency(detail.totals.days61to90);
      detail.totals.over90Days = roundToCurrency(detail.totals.over90Days);
      detail.totals.total = roundToCurrency(detail.totals.total);

      return detail;

    } catch (error) {
      this.logger.error('Failed to get customer aging detail', error, {
        customerId,
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Update overdue invoice statuses
   */
  async updateOverdueStatuses(businessId: string): Promise<{
    updatedInvoices: number;
    overdueTotal: number;
  }> {
    if (!this.db) {
      throw new Error('Database not initialized');
    }

    const validBusinessId = validateBusinessId(businessId);
    const now = Date.now();

    try {
      // Get invoices that are past due but not marked as overdue
      const overdueResult = await this.db.prepare(`
        SELECT id, invoice_number, balance_due
        FROM invoices
        WHERE business_id = ?
        AND status IN ('SENT', 'VIEWED', 'PARTIALLY_PAID')
        AND due_date < ?
        AND balance_due > 0
      `).bind(validBusinessId, now).all();

      const overdueInvoices = overdueResult.results || [];
      let overdueTotal = 0;

      if (overdueInvoices.length > 0) {
        // Update status to overdue
        await this.db.prepare(`
          UPDATE invoices
          SET status = 'OVERDUE', updated_at = ?
          WHERE business_id = ?
          AND status IN ('SENT', 'VIEWED', 'PARTIALLY_PAID')
          AND due_date < ?
          AND balance_due > 0
        `).bind(now, validBusinessId, now).run();

        overdueTotal = overdueInvoices.reduce((sum, inv) => sum + (inv.balance_due as number), 0);

        this.logger.info('Updated overdue invoice statuses', {
          count: overdueInvoices.length,
          overdueTotal: roundToCurrency(overdueTotal),
          businessId: validBusinessId
        });
      }

      return {
        updatedInvoices: overdueInvoices.length,
        overdueTotal: roundToCurrency(overdueTotal)
      };

    } catch (error) {
      this.logger.error('Failed to update overdue statuses', error, {
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Get payment terms suggestions based on customer history
   */
  async getPaymentTermsSuggestions(
    customerId: string,
    businessId: string
  ): Promise<{
    recommendedTerms: PaymentTerms;
    averagePaymentDays: number;
    onTimePaymentRate: number;
    totalInvoices: number;
  }> {
    if (!this.db) {
      throw new Error('Database not initialized');
    }

    const validBusinessId = validateBusinessId(businessId);

    try {
      // Get payment history for customer
      const paymentHistory = await this.db.prepare(`
        SELECT
          i.due_date,
          p.payment_date,
          i.total
        FROM invoices i
        INNER JOIN invoice_payments p ON i.id = p.invoice_id
        WHERE i.customer_id = ?
        AND i.business_id = ?
        AND i.status = 'PAID'
        ORDER BY p.payment_date DESC
        LIMIT 50
      `).bind(customerId, validBusinessId).all();

      const payments = paymentHistory.results || [];

      if (payments.length === 0) {
        // Default terms for new customers
        return {
          recommendedTerms: {
            type: PaymentTermType.NET,
            netDays: 30,
            description: 'Net 30 days'
          },
          averagePaymentDays: 0,
          onTimePaymentRate: 0,
          totalInvoices: 0
        };
      }

      let totalPaymentDays = 0;
      let onTimePayments = 0;

      for (const payment of payments) {
        const dueDate = payment.due_date as number;
        const paymentDate = payment.payment_date as number;
        const paymentDays = Math.floor((paymentDate - dueDate) / (1000 * 60 * 60 * 24));

        totalPaymentDays += Math.max(0, paymentDays);

        if (paymentDate <= dueDate) {
          onTimePayments++;
        }
      }

      const averagePaymentDays = totalPaymentDays / payments.length;
      const onTimePaymentRate = onTimePayments / payments.length;

      // Determine recommended terms based on payment history
      let recommendedTerms: PaymentTerms;

      if (onTimePaymentRate >= 0.9 && averagePaymentDays <= 5) {
        // Excellent payment history - offer discount terms
        recommendedTerms = {
          type: PaymentTermType.NET,
          netDays: 30,
          discountDays: 10,
          discountPercentage: 2,
          description: '2/10 Net 30'
        };
      } else if (onTimePaymentRate >= 0.7) {
        // Good payment history - standard terms
        recommendedTerms = {
          type: PaymentTermType.NET,
          netDays: 30,
          description: 'Net 30 days'
        };
      } else if (onTimePaymentRate >= 0.5) {
        // Fair payment history - shorter terms
        recommendedTerms = {
          type: PaymentTermType.NET,
          netDays: 15,
          description: 'Net 15 days'
        };
      } else {
        // Poor payment history - strict terms
        recommendedTerms = {
          type: PaymentTermType.DUE_ON_RECEIPT,
          description: 'Due on receipt'
        };
      }

      return {
        recommendedTerms,
        averagePaymentDays: Math.round(averagePaymentDays),
        onTimePaymentRate: Math.round(onTimePaymentRate * 100) / 100,
        totalInvoices: payments.length
      };

    } catch (error) {
      this.logger.error('Failed to get payment terms suggestions', error, {
        customerId,
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Determine aging bucket for days past due
   */
  private getAgingBucket(daysPastDue: number): 'current' | '1-30' | '31-60' | '61-90' | '90+' {
    if (daysPastDue <= 0) {
      return 'current';
    } else if (daysPastDue <= 30) {
      return '1-30';
    } else if (daysPastDue <= 60) {
      return '31-60';
    } else if (daysPastDue <= 90) {
      return '61-90';
    } else {
      return '90+';
    }
  }

  /**
   * Create standard payment terms
   */
  static createStandardTerms(): {
    net30: PaymentTerms;
    net15: PaymentTerms;
    dueOnReceipt: PaymentTerms;
    net30With2Percent10: PaymentTerms;
    endOfMonth: PaymentTerms;
  } {
    return {
      net30: {
        type: PaymentTermType.NET,
        netDays: 30,
        description: 'Net 30 days'
      },
      net15: {
        type: PaymentTermType.NET,
        netDays: 15,
        description: 'Net 15 days'
      },
      dueOnReceipt: {
        type: PaymentTermType.DUE_ON_RECEIPT,
        description: 'Due on receipt'
      },
      net30With2Percent10: {
        type: PaymentTermType.NET,
        netDays: 30,
        discountDays: 10,
        discountPercentage: 2,
        description: '2/10 Net 30'
      },
      endOfMonth: {
        type: PaymentTermType.END_OF_MONTH,
        description: 'End of month'
      }
    };
  }
}