/**
 * Invoice Management System
 * Handles invoice creation, line items, and integration with ledger
 */

import type { D1Database, KVNamespace } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';
import { JournalEntryManager } from './journal-entry-manager';
import { FinanceAuditLogger } from './audit-logger';
import { TaxCalculationEngine } from './tax-calculation-engine';
import { PaymentTermsManager } from './payment-terms-manager';
import { CurrencyManager } from './currency-manager';
import {
  Invoice,
  InvoiceLine,
  InvoiceStatus,
  ApprovalStatus,
  CreateInvoiceRequest,
  UpdateInvoiceRequest,
  InvoiceApproval,
  Customer,
  TaxLine,
  InvoiceDiscount,
  JournalEntryType,
  PaymentTermType
} from './types';
import { validateBusinessId, generateInvoiceNumber, roundToCurrency } from './utils';

export // TODO: Consider splitting InvoiceManager into smaller, focused classes
class InvoiceManager {
  private logger: Logger;
  private db: D1Database;
  private kv?: KVNamespace;
  private journalManager: JournalEntryManager;
  private auditLogger: FinanceAuditLogger;
  private taxEngine: TaxCalculationEngine;
  private paymentTermsManager: PaymentTermsManager;
  private currencyManager: CurrencyManager;

  constructor(
    db: D1Database,
    journalManager: JournalEntryManager,
    auditLogger: FinanceAuditLogger,
    currencyManager: CurrencyManager,
    kv?: KVNamespace
  ) {
    this.logger = new Logger();
    this.db = db;
    this.kv = kv;
    this.journalManager = journalManager;
    this.auditLogger = auditLogger;
    this.currencyManager = currencyManager;
    this.taxEngine = new TaxCalculationEngine(db);
    this.paymentTermsManager = new PaymentTermsManager(db, currencyManager);
  }

  /**
   * Create a new invoice
   */
  async createInvoice(
    request: CreateInvoiceRequest,
    createdBy: string,
    businessId: string
  ): Promise<Invoice> {
    const validBusinessId = validateBusinessId(businessId);
    const now = Date.now();

    try {
      // Get customer details
      const customer = await this.getCustomer(request.customerId, validBusinessId);
      if (!customer) {
        throw new Error('Customer not found');
      }

      // Generate invoice number
      const invoiceNumber = await generateInvoiceNumber(this.db, validBusinessId);
      const invoiceId = `inv_${now}_${Math.random().toString(36).substring(2, 9)}`;

      // Calculate due date
      const dueDate = request.dueDate || this.calculateDueDate(
        request.issueDate,
        request.terms || customer.paymentTerms
      );

      // Process invoice lines
      const lines: InvoiceLine[] = [];
      let subtotal = 0;

      for (let i = 0; i < request.lines.length; i++) {
        const lineRequest = request.lines[i];
        const lineId = `line_${invoiceId}_${i + 1}`;

        // Calculate line discount
        let discountAmount = 0;
        if (lineRequest.discount && lineRequest.discountType) {
          if (lineRequest.discountType === 'percentage') {
            discountAmount = (lineRequest.quantity * lineRequest.unitPrice) * (lineRequest.discount / 100);
          } else {
            discountAmount = lineRequest.discount;
          }
        }

        const lineTotal = (lineRequest.quantity * lineRequest.unitPrice) - discountAmount;
        subtotal += lineTotal;

        const line: InvoiceLine = {
          id: lineId,
          invoiceId,
          productId: undefined,
          description: lineRequest.description,
          quantity: lineRequest.quantity,
          unitPrice: lineRequest.unitPrice,
          discount: lineRequest.discount,
          discountType: lineRequest.discountType,
          lineTotal: roundToCurrency(lineTotal),
          taxableAmount: roundToCurrency(lineTotal),
          taxAmount: 0, // Will be calculated by tax engine
          taxRateId: lineRequest.taxRateId,
          accountId: lineRequest.accountId,
          departmentId: lineRequest.departmentId,
          projectId: lineRequest.projectId
        };

        lines.push(line);
      }

      // Calculate taxes
      const taxCalculation = await this.taxEngine.calculateInvoiceTaxes(lines, validBusinessId);
      const taxTotal = taxCalculation.totalTax;

      // Update line tax amounts
      for (const line of lines) {
        const lineTax = taxCalculation.lineTaxes.find(t => t.lineId === line.id);
        if (lineTax) {
          line.taxAmount = lineTax.taxAmount;
        }
      }

      // Process invoice-level discounts
      const discounts: InvoiceDiscount[] = [];
      let discountTotal = 0;

      if (request.discounts) {
        for (let i = 0; i < request.discounts.length; i++) {
          const discountRequest = request.discounts[i];
          const discountId = `disc_${invoiceId}_${i + 1}`;

          let discountAmount = 0;
          if (discountRequest.type === 'percentage') {
            discountAmount = subtotal * (discountRequest.value / 100);
          } else {
            discountAmount = discountRequest.value;
          }

          discountTotal += discountAmount;

          discounts.push({
            id: discountId,
            invoiceId,
            description: discountRequest.description,
            type: discountRequest.type,
            value: discountRequest.value,
            amount: roundToCurrency(discountAmount)
          });
        }
      }

      // Calculate final totals
      const finalSubtotal = subtotal - discountTotal;
      const total = finalSubtotal + taxTotal;

      // Check if approval is required
      const approvalThreshold = await this.getApprovalThreshold(validBusinessId);
      const approvalRequired = total >= approvalThreshold;

      // Get exchange rate
      const invoiceCurrency = request.currency || customer.currency;
      const baseCurrency = await this.currencyManager.getBaseCurrency(validBusinessId);
      let exchangeRate = 1.0;

      if (invoiceCurrency !== baseCurrency) {
        exchangeRate = await this.currencyManager.getExchangeRate(
          invoiceCurrency,
          validBusinessId,
          request.issueDate
        );
      }

      const invoice: Invoice = {
        id: invoiceId,
        invoiceNumber,
        customerId: customer.id,
        customerName: customer.name,
        customerEmail: customer.email,
        customerAddress: customer.billingAddress,
        billToAddress: request.billToAddress || customer.billingAddress,
        shipToAddress: request.shipToAddress || customer.shippingAddress,
        issueDate: request.issueDate,
        dueDate,
        currency: invoiceCurrency,
        exchangeRate,
        subtotal: roundToCurrency(subtotal),
        taxTotal: roundToCurrency(taxTotal),
        discountTotal: roundToCurrency(discountTotal),
        total: roundToCurrency(total),
        balanceDue: roundToCurrency(total),
        status: approvalRequired ? InvoiceStatus.PENDING_APPROVAL : InvoiceStatus.DRAFT,
        terms: request.terms || customer.paymentTerms,
        lines,
        taxLines: taxCalculation.taxLines,
        discounts: discounts.length > 0 ? discounts : undefined,
        notes: request.notes,
        internalNotes: request.internalNotes,
        referenceNumber: request.referenceNumber,
        poNumber: request.poNumber,
        approvalRequired,
        approvalStatus: approvalRequired ? ApprovalStatus.PENDING : undefined,
        createdAt: now,
        createdBy,
        updatedAt: now,
        businessId: validBusinessId
      };

      // Save to database
      await this.saveInvoice(invoice);

      // Log audit trail
      await this.auditLogger.logAction(
        'invoice',
        invoiceId,
        'CREATE',
        validBusinessId,
        createdBy,
        {
          invoiceNumber,
          customerId: customer.id,
          customerName: customer.name,
          total: invoice.total,
          currency: invoice.currency,
          lineCount: lines.length
        }
      );

      this.logger.info('Invoice created', {
        invoiceId,
        invoiceNumber,
        customerId: customer.id,
        total: invoice.total,
        businessId: validBusinessId
      });

      return invoice;

    } catch (error) {
      this.logger.error('Failed to create invoice', error, {
        customerId: request.customerId,
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Update an existing invoice
   */
  async updateInvoice(
    invoiceId: string,
    request: UpdateInvoiceRequest,
    updatedBy: string,
    businessId: string
  ): Promise<Invoice> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      const existingInvoice = await this.getInvoice(invoiceId, validBusinessId);
      if (!existingInvoice) {
        throw new Error('Invoice not found');
      }

      // Check if invoice can be updated
      if ([InvoiceStatus.SENT, InvoiceStatus.PAID, InvoiceStatus.VOIDED].includes(existingInvoice.status)) {
        throw new Error('Invoice cannot be updated in current status');
      }

      const changes: Record<string, any> = {};

      // Update customer if changed
      let customer = await this.getCustomer(existingInvoice.customerId, validBusinessId);
      if (request.customerId && request.customerId !== existingInvoice.customerId) {
        customer = await this.getCustomer(request.customerId, validBusinessId);
        if (!customer) {
          throw new Error('Customer not found');
        }
        changes.customerId = { from: existingInvoice.customerId, to: request.customerId };
      }

      // Update dates
      const issueDate = request.issueDate || existingInvoice.issueDate;
      const dueDate = request.dueDate || this.calculateDueDate(issueDate, existingInvoice.terms);

      if (issueDate !== existingInvoice.issueDate) {
        changes.issueDate = { from: existingInvoice.issueDate, to: issueDate };
      }
      if (dueDate !== existingInvoice.dueDate) {
        changes.dueDate = { from: existingInvoice.dueDate, to: dueDate };
      }

      // Process updated lines if provided
      let lines = existingInvoice.lines;
      let subtotal = existingInvoice.subtotal;

      if (request.lines) {
        lines = [];
        subtotal = 0;

        for (let i = 0; i < request.lines.length; i++) {
          const lineRequest = request.lines[i];
          const lineId = lineRequest.id || `line_${invoiceId}_${i + 1}`;

          // Calculate line discount
          let discountAmount = 0;
          if (lineRequest.discount && lineRequest.discountType) {
            if (lineRequest.discountType === 'percentage') {
              discountAmount = (lineRequest.quantity * lineRequest.unitPrice) * (lineRequest.discount / 100);
            } else {
              discountAmount = lineRequest.discount;
            }
          }

          const lineTotal = (lineRequest.quantity * lineRequest.unitPrice) - discountAmount;
          subtotal += lineTotal;

          const line: InvoiceLine = {
            id: lineId,
            invoiceId,
            productId: undefined,
            description: lineRequest.description,
            quantity: lineRequest.quantity,
            unitPrice: lineRequest.unitPrice,
            discount: lineRequest.discount,
            discountType: lineRequest.discountType,
            lineTotal: roundToCurrency(lineTotal),
            taxableAmount: roundToCurrency(lineTotal),
            taxAmount: 0,
            taxRateId: lineRequest.taxRateId,
            accountId: lineRequest.accountId
          };

          lines.push(line);
        }

        changes.lines = { lineCount: request.lines.length };
      }

      // Recalculate taxes
      const taxCalculation = await this.taxEngine.calculateInvoiceTaxes(lines, validBusinessId);
      const taxTotal = taxCalculation.totalTax;

      // Update line tax amounts
      for (const line of lines) {
        const lineTax = taxCalculation.lineTaxes.find(t => t.lineId === line.id);
        if (lineTax) {
          line.taxAmount = lineTax.taxAmount;
        }
      }

      const total = subtotal + taxTotal - existingInvoice.discountTotal;

      const updatedInvoice: Invoice = {
        ...existingInvoice,
        customerId: customer!.id,
        customerName: customer!.name,
        customerEmail: customer!.email,
        issueDate,
        dueDate,
        subtotal: roundToCurrency(subtotal),
        taxTotal: roundToCurrency(taxTotal),
        total: roundToCurrency(total),
        balanceDue: roundToCurrency(total - (existingInvoice.total - existingInvoice.balanceDue)),
        lines,
        taxLines: taxCalculation.taxLines,
        notes: request.notes || existingInvoice.notes,
        internalNotes: request.internalNotes || existingInvoice.internalNotes,
        referenceNumber: request.referenceNumber || existingInvoice.referenceNumber,
        poNumber: request.poNumber || existingInvoice.poNumber,
        terms: request.terms || existingInvoice.terms,
        updatedAt: Date.now(),
        updatedBy
      };

      // Save updated invoice
      await this.saveInvoice(updatedInvoice);

      // Log audit trail
      await this.auditLogger.logAction(
        'invoice',
        invoiceId,
        'UPDATE',
        validBusinessId,
        updatedBy,
        changes
      );

      this.logger.info('Invoice updated', {
        invoiceId,
        invoiceNumber: updatedInvoice.invoiceNumber,
        businessId: validBusinessId
      });

      return updatedInvoice;

    } catch (error) {
      this.logger.error('Failed to update invoice', error, {
        invoiceId,
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Post invoice to accounting system
   */
  async postInvoice(
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

      if (invoice.status !== InvoiceStatus.SENT && invoice.status !== InvoiceStatus.VIEWED) {
        throw new Error('Invoice must be sent before posting');
      }

      if (invoice.journalEntryId) {
        throw new Error('Invoice has already been posted');
      }

      // Get account IDs from configuration
      const accountIds = await this.getAccountingConfiguration(validBusinessId);

      // Create journal entry for invoice posting
      const journalLines = [];

      // Debit Accounts Receivable
      journalLines.push({
        accountId: accountIds.accountsReceivableId,
        debit: invoice.total,
        credit: 0,
        description: `Invoice ${invoice.invoiceNumber} - ${invoice.customerName}`,
        customerId: invoice.customerId
      });

      // Credit Revenue accounts (by line)
      for (const line of invoice.lines) {
        if (line.accountId && line.lineTotal > 0) {
          journalLines.push({
            accountId: line.accountId,
            debit: 0,
            credit: line.lineTotal,
            description: `${line.description} - Invoice ${invoice.invoiceNumber}`,
            customerId: invoice.customerId
          });
        }
      }

      // Credit Tax accounts
      if (invoice.taxLines) {
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

      // Create the journal entry
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

      // Update invoice status and journal entry reference
      const updatedInvoice = {
        ...invoice,
        journalEntryId: journalEntry.id,
        updatedAt: Date.now(),
        updatedBy: postedBy
      };

      await this.saveInvoice(updatedInvoice);

      // Log audit trail
      await this.auditLogger.logAction(
        'invoice',
        invoiceId,
        'POST',
        validBusinessId,
        postedBy,
        {
          journalEntryId: journalEntry.id,
          amount: invoice.total
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
      this.logger.error('Failed to post invoice', error, {
        invoiceId,
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Get invoice by ID
   */
  async getInvoice(invoiceId: string, businessId: string): Promise<Invoice | null> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      const result = await this.db.prepare(`
        SELECT * FROM invoices
        WHERE id = ? AND business_id = ?
      `).bind(invoiceId, validBusinessId).first();

      if (!result) {
        return null;
      }

      return this.mapToInvoice(result);

    } catch (error) {
      this.logger.error('Failed to get invoice', error, {
        invoiceId,
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Calculate due date based on payment terms
   */
  private calculateDueDate(issueDate: number, terms: any): number {
    return this.paymentTermsManager.calculateDueDate(issueDate, terms);
  }

  /**
   * Get customer details
   */
  private async getCustomer(customerId: string, businessId: string): Promise<Customer | null> {
    const result = await this.db.prepare(`
      SELECT * FROM customers
      WHERE id = ? AND business_id = ?
    `).bind(customerId, businessId).first();

    if (!result) {
      return null;
    }

    return this.mapToCustomer(result);
  }

  /**
   * Get approval threshold
   */
  private async getApprovalThreshold(businessId: string): Promise<number> {
    const result = await this.db.prepare(`
      SELECT approval_threshold FROM finance_config
      WHERE business_id = ?
    `).bind(businessId).first();

    return (result?.approval_threshold as number) || 0;
  }

  /**
   * Get accounting configuration
   */
  private async getAccountingConfiguration(businessId: string): Promise<{
    accountsReceivableId: string;
    salesTaxPayableId: string;
  }> {
    const result = await this.db.prepare(`
      SELECT accounts_receivable_id, sales_tax_payable_id
      FROM finance_config
      WHERE business_id = ?
    `).bind(businessId).first();

    if (!result) {
      throw new Error('Accounting configuration not found');
    }

    return {
      accountsReceivableId: result.accounts_receivable_id as string,
      salesTaxPayableId: result.sales_tax_payable_id as string
    };
  }

  /**
   * Save invoice to database
   */
  private async saveInvoice(invoice: Invoice): Promise<void> {
    await this.db.prepare(`
      INSERT OR REPLACE INTO invoices (
        id, invoice_number, customer_id, customer_name, customer_email,
        issue_date, due_date, currency, exchange_rate,
        subtotal, tax_total, discount_total, total, balance_due,
        status, terms, lines, tax_lines, discounts,
        notes, internal_notes, reference_number, po_number,
        approval_required, approval_status, approvals,
        pdf_url, sent_at, sent_by, last_reminder_sent,
        journal_entry_id, created_at, created_by, updated_at, updated_by,
        business_id, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
  ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      invoice.id,
      invoice.invoiceNumber,
      invoice.customerId,
      invoice.customerName,
      invoice.customerEmail || null,
      invoice.issueDate,
      invoice.dueDate,
      invoice.currency,
      invoice.exchangeRate,
      invoice.subtotal,
      invoice.taxTotal,
      invoice.discountTotal,
      invoice.total,
      invoice.balanceDue,
      invoice.status,
      JSON.stringify(invoice.terms),
      JSON.stringify(invoice.lines),
      invoice.taxLines ? JSON.stringify(invoice.taxLines) : null,
      invoice.discounts ? JSON.stringify(invoice.discounts) : null,
      invoice.notes || null,
      invoice.internalNotes || null,
      invoice.referenceNumber || null,
      invoice.poNumber || null,
      invoice.approvalRequired ? 1 : 0,
      invoice.approvalStatus || null,
      invoice.approvals ? JSON.stringify(invoice.approvals) : null,
      invoice.pdfUrl || null,
      invoice.sentAt || null,
      invoice.sentBy || null,
      invoice.lastReminderSent || null,
      invoice.journalEntryId || null,
      invoice.createdAt,
      invoice.createdBy,
      invoice.updatedAt,
      invoice.updatedBy || null,
      invoice.businessId,
      invoice.metadata ? JSON.stringify(invoice.metadata) : null
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
      approvalStatus: row.approval_status as ApprovalStatus || undefined,
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

  /**
   * Map database row to Customer
   */
  private mapToCustomer(row: any): Customer {
    return {
      id: row.id,
      name: row.name,
      email: row.email || undefined,
      phone: row.phone || undefined,
      website: row.website || undefined,
      taxId: row.tax_id || undefined,
      currency: row.currency,
      paymentTerms: JSON.parse(row.payment_terms),
      creditLimit: row.credit_limit || undefined,
      billingAddress: row.billing_address ? JSON.parse(row.billing_address) : undefined,
      shippingAddress: row.shipping_address ? JSON.parse(row.shipping_address) : undefined,
      contacts: row.contacts ? JSON.parse(row.contacts) : undefined,
      isActive: Boolean(row.is_active),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      businessId: row.business_id,
      metadata: row.metadata ? JSON.parse(row.metadata) : undefined
    };
  }
}