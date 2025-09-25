/**
 * Invoice Posting Manager
 * Handles automatic posting of invoices to AR and Revenue accounts
 */

import type { D1Database } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';
import { JournalEntryManager } from './journal-entry-manager';
import { FinanceAuditLogger } from './audit-logger';
import {
  Invoice,
  InvoiceStatus,
  InvoicePayment,
  PaymentMethod,
  JournalEntryType,
  RecordPaymentRequest,
  ChartAccount,
  AccountType
} from './types';
import { validateBusinessId, roundToCurrency } from './utils';

export interface PostingConfiguration {
  accountsReceivableId: string;
  salesTaxPayableId: string;
  defaultRevenueAccountId: string;
  discountAllowedAccountId?: string;
  badDebtAccountId?: string;
  unallocatedCashAccountId?: string;
  cashAccountId: string;
}

export interface PaymentAllocation {
  invoiceId: string;
  allocatedAmount: number;
  remainingBalance: number;
}

export // TODO: Consider splitting InvoicePostingManager into smaller, focused classes
class InvoicePostingManager {
  private logger: Logger;
  private db: D1Database;
  private journalManager: JournalEntryManager;
  private auditLogger: FinanceAuditLogger;

  constructor(
    db: D1Database,
    journalManager: JournalEntryManager,
    auditLogger: FinanceAuditLogger
  ) {
    this.logger = new Logger();
    this.db = db;
    this.journalManager = journalManager;
    this.auditLogger = auditLogger;
  }

  /**
   * Post invoice to create AR and Revenue entries
   */
  async postInvoiceToLedger(
    invoiceId: string,
    postedBy: string,
    businessId: string
  ): Promise<{ invoice: Invoice; journalEntryId: string }> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      const invoice = await this.getInvoice(invoiceId, validBusinessId);
      if (!invoice) {
        throw new Error('Invoice not found');
      }

      if (![InvoiceStatus.SENT, InvoiceStatus.VIEWED].includes(invoice.status)) {
        throw new Error('Invoice must be sent before posting to ledger');
      }

      if (invoice.journalEntryId) {
        throw new Error('Invoice has already been posted to ledger');
      }

      const config = await this.getPostingConfiguration(validBusinessId);
      const journalLines = [];

      // Debit Accounts Receivable for total invoice amount
      journalLines.push({
        accountId: config.accountsReceivableId,
        debit: invoice.total,
        credit: 0,
        description: `Invoice ${invoice.invoiceNumber} - ${invoice.customerName}`,
        customerId: invoice.customerId
      });

      // Credit Revenue accounts for each line item
      for (const line of invoice.lines) {
        const revenueAccountId = line.accountId || config.defaultRevenueAccountId;

        journalLines.push({
          accountId: revenueAccountId,
          debit: 0,
          credit: line.lineTotal,
          description: `${line.description} - Invoice ${invoice.invoiceNumber}`,
          customerId: invoice.customerId,
          departmentId: line.departmentId,
          projectId: line.projectId
        });
      }

      // Credit Tax accounts for tax amounts
      if (invoice.taxLines && invoice.taxLines.length > 0) {
        for (const taxLine of invoice.taxLines) {
          journalLines.push({
            accountId: taxLine.accountId,
            debit: 0,
            credit: taxLine.taxAmount,
            description: `${taxLine.taxName} - Invoice ${invoice.invoiceNumber}`,
            customerId: invoice.customerId
          });
        }
      }

      // Create journal entry
      const journalEntry = await this.journalManager.createJournalEntry(
        {
          date: invoice.issueDate,
          description: `Invoice ${invoice.invoiceNumber} - ${invoice.customerName}`,
          reference: invoice.invoiceNumber,
          type: JournalEntryType.SYSTEM,
          lines: journalLines
        },
        postedBy,
        validBusinessId
      );

      // Post the journal entry
      await this.journalManager.postJournalEntry(
        { journalEntryId: journalEntry.id },
        postedBy,
        validBusinessId
      );

      // Update invoice with journal entry reference
      const updatedInvoice = await this.updateInvoiceJournalEntry(
        invoiceId,
        journalEntry.id,
        postedBy,
        validBusinessId
      );

      // Log audit trail
      await this.auditLogger.logAction(
        'invoice',
        invoiceId,
        'POST',
        validBusinessId,
        postedBy,
        {
          journalEntryId: journalEntry.id,
          amount: invoice.total,
          accountsReceivableId: config.accountsReceivableId
        }
      );

      this.logger.info('Invoice posted to ledger', {
        invoiceId,
        invoiceNumber: invoice.invoiceNumber,
        journalEntryId: journalEntry.id,
        total: invoice.total,
        businessId: validBusinessId
      });

      return {
        invoice: updatedInvoice,
        journalEntryId: journalEntry.id
      };

    } catch (error) {
      this.logger.error('Failed to post invoice to ledger', error, {
        invoiceId,
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Record payment against invoice(s)
   */
  async recordPayment(
    request: RecordPaymentRequest,
    recordedBy: string,
    businessId: string
  ): Promise<{
    payment: InvoicePayment;
    allocations: PaymentAllocation[];
    journalEntryId: string;
  }> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      const invoice = await this.getInvoice(request.invoiceId, validBusinessId);
      if (!invoice) {
        throw new Error('Invoice not found');
      }

      if (invoice.balanceDue <= 0) {
        throw new Error('Invoice has no outstanding balance');
      }

      if (request.amount <= 0) {
        throw new Error('Payment amount must be greater than zero');
      }

      if (request.amount > invoice.balanceDue) {
        throw new Error('Payment amount cannot exceed balance due');
      }

      const config = await this.getPostingConfiguration(validBusinessId);
      const paymentId = `pmt_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;

      // Create payment record
      const payment: InvoicePayment = {
        id: paymentId,
        invoiceId: request.invoiceId,
        paymentDate: request.paymentDate,
        amount: request.amount,
        currency: invoice.currency,
        exchangeRate: invoice.exchangeRate,
        baseAmount: roundToCurrency(request.amount * invoice.exchangeRate),
        paymentMethod: request.paymentMethod,
        reference: request.reference,
        notes: request.notes,
        createdAt: Date.now(),
        createdBy: recordedBy,
        businessId: validBusinessId
      };

      // Determine cash account
      const cashAccountId = request.accountId || await this.getCashAccountForPaymentMethod(
        request.paymentMethod,
        validBusinessId,
        request.amount,
        invoice.currency
      );

      // Create journal entry for payment
      const journalLines = [
        {
          accountId: cashAccountId,
          debit: request.amount,
          credit: 0,
          description: `Payment received - Invoice ${invoice.invoiceNumber}`,
          customerId: invoice.customerId
        },
        {
          accountId: config.accountsReceivableId,
          debit: 0,
          credit: request.amount,
          description: `Payment applied - Invoice ${invoice.invoiceNumber}`,
          customerId: invoice.customerId
        }
      ];

      const journalEntry = await this.journalManager.createJournalEntry(
        {
          date: request.paymentDate,
          description: `Payment received - Invoice ${invoice.invoiceNumber}`,
          reference: request.reference || payment.id,
          type: JournalEntryType.SYSTEM,
          lines: journalLines
        },
        recordedBy,
        validBusinessId
      );

      // Post the journal entry
      await this.journalManager.postJournalEntry(
        { journalEntryId: journalEntry.id },
        recordedBy,
        validBusinessId
      );

      // Update payment with journal entry ID
      payment.journalEntryId = journalEntry.id;

      // Save payment to database
      await this.savePayment(payment);

      // Update invoice balance
      const newBalance = roundToCurrency(invoice.balanceDue - request.amount);
      const newStatus = newBalance <= 0 ? InvoiceStatus.PAID : InvoiceStatus.PARTIALLY_PAID;

      await this.updateInvoiceBalance(
        request.invoiceId,
        newBalance,
        newStatus,
        recordedBy,
        validBusinessId
      );

      // Create allocation record
      const allocation: PaymentAllocation = {
        invoiceId: request.invoiceId,
        allocatedAmount: request.amount,
        remainingBalance: newBalance
      };

      // Log audit trail
      await this.auditLogger.logAction(
        'payment',
        paymentId,
        'CREATE',
        validBusinessId,
        recordedBy,
        {
          invoiceId: request.invoiceId,
          invoiceNumber: invoice.invoiceNumber,
          amount: request.amount,
          paymentMethod: request.paymentMethod,
          journalEntryId: journalEntry.id
        }
      );

      this.logger.info('Payment recorded', {
        paymentId,
        invoiceId: request.invoiceId,
        invoiceNumber: invoice.invoiceNumber,
        amount: request.amount,
        newBalance,
        businessId: validBusinessId
      });

      return {
        payment,
        allocations: [allocation],
        journalEntryId: journalEntry.id
      };

    } catch (error) {
      this.logger.error('Failed to record payment', error, {
        invoiceId: request.invoiceId,
        amount: request.amount,
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Apply early payment discount
   */
  async applyEarlyPaymentDiscount(
    invoiceId: string,
    discountAmount: number,
    appliedBy: string,
    businessId: string
  ): Promise<{ journalEntryId: string }> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      const invoice = await this.getInvoice(invoiceId, validBusinessId);
      if (!invoice) {
        throw new Error('Invoice not found');
      }

      if (discountAmount <= 0) {
        throw new Error('Discount amount must be greater than zero');
      }

      if (discountAmount > invoice.balanceDue) {
        throw new Error('Discount amount cannot exceed balance due');
      }

      const config = await this.getPostingConfiguration(validBusinessId);

      if (!config.discountAllowedAccountId) {
        throw new Error('Discount allowed account not configured');
      }

      // Create journal entry for discount
      const journalLines = [
        {
          accountId: config.discountAllowedAccountId,
          debit: discountAmount,
          credit: 0,
          description: `Early payment discount - Invoice ${invoice.invoiceNumber}`,
          customerId: invoice.customerId
        },
        {
          accountId: config.accountsReceivableId,
          debit: 0,
          credit: discountAmount,
          description: `Discount applied - Invoice ${invoice.invoiceNumber}`,
          customerId: invoice.customerId
        }
      ];

      const journalEntry = await this.journalManager.createJournalEntry(
        {
          date: Date.now(),
          description: `Early payment discount - Invoice ${invoice.invoiceNumber}`,
          reference: invoice.invoiceNumber,
          type: JournalEntryType.SYSTEM,
          lines: journalLines
        },
        appliedBy,
        validBusinessId
      );

      // Post the journal entry
      await this.journalManager.postJournalEntry(
        { journalEntryId: journalEntry.id },
        appliedBy,
        validBusinessId
      );

      // Update invoice balance
      const newBalance = roundToCurrency(invoice.balanceDue - discountAmount);
      const newStatus = newBalance <= 0 ? InvoiceStatus.PAID : InvoiceStatus.PARTIALLY_PAID;

      await this.updateInvoiceBalance(
        invoiceId,
        newBalance,
        newStatus,
        appliedBy,
        validBusinessId
      );

      // Log audit trail
      await this.auditLogger.logAction(
        'invoice',
        invoiceId,
        'DISCOUNT',
        validBusinessId,
        appliedBy,
        {
          discountAmount,
          journalEntryId: journalEntry.id
        }
      );

      this.logger.info('Early payment discount applied', {
        invoiceId,
        invoiceNumber: invoice.invoiceNumber,
        discountAmount,
        newBalance,
        businessId: validBusinessId
      });

      return { journalEntryId: journalEntry.id };

    } catch (error) {
      this.logger.error('Failed to apply early payment discount', error, {
        invoiceId,
        discountAmount,
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Write off bad debt
   */
  async writeOffBadDebt(
    invoiceId: string,
    writeOffAmount: number,
    reason: string,
    writtenOffBy: string,
    businessId: string
  ): Promise<{ journalEntryId: string }> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      const invoice = await this.getInvoice(invoiceId, validBusinessId);
      if (!invoice) {
        throw new Error('Invoice not found');
      }

      if (writeOffAmount <= 0) {
        throw new Error('Write-off amount must be greater than zero');
      }

      if (writeOffAmount > invoice.balanceDue) {
        throw new Error('Write-off amount cannot exceed balance due');
      }

      const config = await this.getPostingConfiguration(validBusinessId);

      if (!config.badDebtAccountId) {
        throw new Error('Bad debt account not configured');
      }

      // Create journal entry for write-off
      const journalLines = [
        {
          accountId: config.badDebtAccountId,
          debit: writeOffAmount,
          credit: 0,
          description: `Bad debt write-off - Invoice ${invoice.invoiceNumber}: ${reason}`,
          customerId: invoice.customerId
        },
        {
          accountId: config.accountsReceivableId,
          debit: 0,
          credit: writeOffAmount,
          description: `Write-off applied - Invoice ${invoice.invoiceNumber}`,
          customerId: invoice.customerId
        }
      ];

      const journalEntry = await this.journalManager.createJournalEntry(
        {
          date: Date.now(),
          description: `Bad debt write-off - Invoice ${invoice.invoiceNumber}`,
          reference: invoice.invoiceNumber,
          type: JournalEntryType.SYSTEM,
          lines: journalLines
        },
        writtenOffBy,
        validBusinessId
      );

      // Post the journal entry
      await this.journalManager.postJournalEntry(
        { journalEntryId: journalEntry.id },
        writtenOffBy,
        validBusinessId
      );

      // Update invoice balance
      const newBalance = roundToCurrency(invoice.balanceDue - writeOffAmount);
      const newStatus = newBalance <= 0 ? InvoiceStatus.PAID : InvoiceStatus.PARTIALLY_PAID;

      await this.updateInvoiceBalance(
        invoiceId,
        newBalance,
        newStatus,
        writtenOffBy,
        validBusinessId
      );

      // Log audit trail
      await this.auditLogger.logAction(
        'invoice',
        invoiceId,
        'WRITE_OFF',
        validBusinessId,
        writtenOffBy,
        {
          writeOffAmount,
          reason,
          journalEntryId: journalEntry.id
        }
      );

      this.logger.info('Bad debt written off', {
        invoiceId,
        invoiceNumber: invoice.invoiceNumber,
        writeOffAmount,
        reason,
        newBalance,
        businessId: validBusinessId
      });

      return { journalEntryId: journalEntry.id };

    } catch (error) {
      this.logger.error('Failed to write off bad debt', error, {
        invoiceId,
        writeOffAmount,
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Get posting configuration
   */
  private async getPostingConfiguration(businessId: string): Promise<PostingConfiguration> {
    const result = await this.db.prepare(`
      SELECT
        accounts_receivable_id,
        sales_tax_payable_id,
        default_revenue_account_id,
        discount_allowed_account_id,
        bad_debt_account_id,
        unallocated_cash_account_id,
        cash_account_id
      FROM finance_config
      WHERE business_id = ?
    `).bind(businessId).first();

    if (!result) {
      throw new Error('Finance configuration not found');
    }

    return {
      accountsReceivableId: result.accounts_receivable_id as string,
      salesTaxPayableId: result.sales_tax_payable_id as string,
      defaultRevenueAccountId: result.default_revenue_account_id as string,
      discountAllowedAccountId: result.discount_allowed_account_id as string || undefined,
      badDebtAccountId: result.bad_debt_account_id as string || undefined,
      unallocatedCashAccountId: result.unallocated_cash_account_id as string || undefined,
      cashAccountId: result.cash_account_id as string
    };
  }

  /**
   * Get appropriate cash account for payment method
   */
  private async getCashAccountForPaymentMethod(
    paymentMethod: PaymentMethod,
    businessId: string,
    amount?: number,
    currency?: string
  ): Promise<string> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      // First, get the payment method configuration
      const paymentMethodResult = await this.db.prepare(`
        SELECT id, method_type, fees_percentage, fees_fixed_amount
        FROM payment_methods_config
        WHERE method_type = ? AND business_id = ? AND is_active = 1
      `).bind(paymentMethod, validBusinessId).first();

      if (!paymentMethodResult) {
        // If no specific configuration found, try to get default cash account
        const config = await this.getPostingConfiguration(validBusinessId);
        return config.cashAccountId;
      }

      const paymentMethodId = paymentMethodResult.id as string;

      // Check for specific rules based on amount, currency, etc.
      if (amount || currency) {
        const rulesResult = await this.db.prepare(`
          SELECT target_account_id, conditions, priority
          FROM payment_processing_rules
          WHERE payment_method_id = ? AND business_id = ? AND is_active = 1
          AND effective_date <= ? AND (expiry_date IS NULL OR expiry_date > ?)
          ORDER BY priority DESC
        `).bind(
          paymentMethodId,
          validBusinessId,
          Date.now(),
          Date.now()
        ).all();

        // Evaluate rules to find the best match
        for (const rule of rulesResult.results || []) {
          try {
            const conditions = JSON.parse(rule.conditions as string);
            if (this.evaluatePaymentRule(conditions, { amount, currency, paymentMethod })) {
              return rule.target_account_id as string;
            }
          } catch (error) {
            this.logger.warn('Invalid payment rule conditions', { ruleId: rule.id, error });
          }
        }
      }

      // Get the primary account for this payment method
      const accountResult = await this.db.prepare(`
        SELECT account_id
        FROM payment_method_accounts
        WHERE payment_method_id = ? AND business_id = ? AND is_primary = 1
        AND effective_date <= ? AND (expiry_date IS NULL OR expiry_date > ?)
        ORDER BY effective_date DESC
        LIMIT 1
      `).bind(
        paymentMethodId,
        validBusinessId,
        Date.now(),
        Date.now()
      ).first();

      if (accountResult) {
        return accountResult.account_id as string;
      }

      // Fall back to any active account for this payment method
      const fallbackResult = await this.db.prepare(`
        SELECT account_id
        FROM payment_method_accounts
        WHERE payment_method_id = ? AND business_id = ?
        AND effective_date <= ? AND (expiry_date IS NULL OR expiry_date > ?)
        ORDER BY effective_date DESC
        LIMIT 1
      `).bind(
        paymentMethodId,
        validBusinessId,
        Date.now(),
        Date.now()
      ).first();

      if (fallbackResult) {
        return fallbackResult.account_id as string;
      }

      // Ultimate fallback to default cash account
      const config = await this.getPostingConfiguration(validBusinessId);
      return config.cashAccountId;

    } catch (error) {
      this.logger.error('Failed to get cash account for payment method', error, {
        paymentMethod,
        businessId: validBusinessId
      });

      // Return default cash account on error
      const config = await this.getPostingConfiguration(validBusinessId);
      return config.cashAccountId;
    }
  }

  /**
   * Evaluate payment processing rule conditions
   */
  private evaluatePaymentRule(
    conditions: any,
    context: { amount?: number; currency?: string; paymentMethod: PaymentMethod }
  ): boolean {
    try {
      // Amount range conditions
      if (conditions.amount_min !== undefined && context.amount !== undefined) {
        if (context.amount < conditions.amount_min) return false;
      }
      if (conditions.amount_max !== undefined && context.amount !== undefined) {
        if (context.amount > conditions.amount_max) return false;
      }

      // Currency conditions
      if (conditions.currencies && context.currency) {
        if (!conditions.currencies.includes(context.currency)) return false;
      }

      // Payment method conditions (for rules that apply to multiple methods)
      if (conditions.payment_methods) {
        if (!conditions.payment_methods.includes(context.paymentMethod)) return false;
      }

      // Time-based conditions (e.g., business hours, weekends)
      if (conditions.time_restrictions) {
        const now = new Date();
        const currentHour = now.getHours();
        const currentDay = now.getDay(); // 0 = Sunday, 1 = Monday, etc.

        if (conditions.time_restrictions.business_hours_only) {
          const businessStart = conditions.time_restrictions.business_start || 9;
          const businessEnd = conditions.time_restrictions.business_end || 17;
          if (currentHour < businessStart || currentHour >= businessEnd) return false;
        }

        if (conditions.time_restrictions.weekdays_only) {
          if (currentDay === 0 || currentDay === 6) return false; // Weekend
        }
      }

      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get fees account for payment method
   */
  private async getFeesAccountForPaymentMethod(
    paymentMethod: PaymentMethod,
    businessId: string
  ): Promise<string | null> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      // Get the payment method configuration
      const paymentMethodResult = await this.db.prepare(`
        SELECT id FROM payment_methods_config
        WHERE method_type = ? AND business_id = ? AND is_active = 1
      `).bind(paymentMethod, validBusinessId).first();

      if (!paymentMethodResult) {
        return null;
      }

      const paymentMethodId = paymentMethodResult.id as string;

      // Get the fees account for this payment method
      const accountResult = await this.db.prepare(`
        SELECT account_id
        FROM payment_method_accounts
        WHERE payment_method_id = ? AND business_id = ? AND is_fees_account = 1
        AND effective_date <= ? AND (expiry_date IS NULL OR expiry_date > ?)
        ORDER BY effective_date DESC
        LIMIT 1
      `).bind(
        paymentMethodId,
        validBusinessId,
        Date.now(),
        Date.now()
      ).first();

      return accountResult ? accountResult.account_id as string : null;

    } catch (error) {
      this.logger.error('Failed to get fees account for payment method', error, {
        paymentMethod,
        businessId: validBusinessId
      });
      return null;
    }
  }

  /**
   * Get invoice
   */
  private async getInvoice(invoiceId: string, businessId: string): Promise<Invoice | null> {
    const result = await this.db.prepare(`
      SELECT * FROM invoices
      WHERE id = ? AND business_id = ?
    `).bind(invoiceId, businessId).first();

    if (!result) {
      return null;
    }

    return this.mapToInvoice(result);
  }

  /**
   * Update invoice journal entry reference
   */
  private async updateInvoiceJournalEntry(
    invoiceId: string,
    journalEntryId: string,
    updatedBy: string,
    businessId: string
  ): Promise<Invoice> {
    await this.db.prepare(`
      UPDATE invoices
      SET journal_entry_id = ?, updated_at = ?, updated_by = ?
      WHERE id = ? AND business_id = ?
    `).bind(journalEntryId, Date.now(), updatedBy, invoiceId, businessId).run();

    const updatedInvoice = await this.getInvoice(invoiceId, businessId);
    if (!updatedInvoice) {
      throw new Error('Failed to retrieve updated invoice');
    }

    return updatedInvoice;
  }

  /**
   * Update invoice balance
   */
  private async updateInvoiceBalance(
    invoiceId: string,
    newBalance: number,
    newStatus: InvoiceStatus,
    updatedBy: string,
    businessId: string
  ): Promise<void> {
    await this.db.prepare(`
      UPDATE invoices
      SET balance_due = ?, status = ?, updated_at = ?, updated_by = ?
      WHERE id = ? AND business_id = ?
    `).bind(newBalance, newStatus, Date.now(), updatedBy, invoiceId, businessId).run();
  }

  /**
   * Save payment to database
   */
  private async savePayment(payment: InvoicePayment): Promise<void> {
    await this.db.prepare(`
      INSERT INTO invoice_payments (
        id, invoice_id, payment_date, amount, currency, exchange_rate,
        base_amount, payment_method, reference, notes, journal_entry_id,
        created_at, created_by, business_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      payment.id,
      payment.invoiceId,
      payment.paymentDate,
      payment.amount,
      payment.currency,
      payment.exchangeRate,
      payment.baseAmount,
      payment.paymentMethod,
      payment.reference || null,
      payment.notes || null,
      payment.journalEntryId || null,
      payment.createdAt,
      payment.createdBy,
      payment.businessId
    ).run();
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
      customerEmail: row.customer_email || undefined,
      customerAddress: row.customer_address ? JSON.parse(row.customer_address) : undefined,
      billToAddress: row.bill_to_address ? JSON.parse(row.bill_to_address) : undefined,
      shipToAddress: row.ship_to_address ? JSON.parse(row.ship_to_address) : undefined,
      issueDate: row.issue_date,
      dueDate: row.due_date,
      currency: row.currency,
      exchangeRate: row.exchange_rate,
      subtotal: row.subtotal,
      taxTotal: row.tax_total,
      discountTotal: row.discount_total,
      total: row.total,
      balanceDue: row.balance_due,
      status: row.status as InvoiceStatus,
      terms: JSON.parse(row.terms),
      lines: JSON.parse(row.lines),
      taxLines: row.tax_lines ? JSON.parse(row.tax_lines) : undefined,
      discounts: row.discounts ? JSON.parse(row.discounts) : undefined,
      notes: row.notes || undefined,
      internalNotes: row.internal_notes || undefined,
      referenceNumber: row.reference_number || undefined,
      poNumber: row.po_number || undefined,
      journalEntryId: row.journal_entry_id || undefined,
      approvalRequired: Boolean(row.approval_required),
      approvalStatus: row.approval_status || undefined,
      approvals: row.approvals ? JSON.parse(row.approvals) : undefined,
      pdfUrl: row.pdf_url || undefined,
      sentAt: row.sent_at || undefined,
      sentBy: row.sent_by || undefined,
      lastReminderSent: row.last_reminder_sent || undefined,
      createdAt: row.created_at,
      createdBy: row.created_by,
      updatedAt: row.updated_at,
      updatedBy: row.updated_by || undefined,
      businessId: row.business_id,
      metadata: row.metadata ? JSON.parse(row.metadata) : undefined
    };
  }
}