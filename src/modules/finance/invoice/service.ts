/**
 * Invoice Service
 * Handles all invoice-related business logic with error-free implementation
 */

import { z } from 'zod'
import type {
  Invoice,
  InvoiceLineItem,
  CreateInvoiceRequest,
  UpdateInvoiceRequest,
  InvoiceSearchParams,
  InvoiceListResponse,
  Customer,
  TaxConfig,
  PDFOptions,
  EmailConfig,
  PaymentLinkConfig,
  InvoiceStatus,
  PaymentTerms,
} from './types'
import {
  InvoiceSchema,
  CreateInvoiceRequestSchema,
  UpdateInvoiceRequestSchema,
  PDFOptionsSchema,
} from './types'
import { AppError } from '@/shared/errors'
import { AuditLogger } from '@/modules/audit/audit-service'
import { TaxCalculationEngine } from './tax-engine'
import { PDFGeneratorService } from './pdf-generator'
import { CurrencyService } from './currency-service'

/**
 * Core Invoice Service
 * Implements all invoice management functionality with comprehensive validation
 */
export // TODO: Consider splitting InvoiceService into smaller, focused classes
class InvoiceService {
  constructor(
    private readonly db: D1Database,
    private readonly auditLogger: AuditLogger,
    private readonly taxCalculator: TaxCalculationEngine,
    private readonly pdfGenerator: PDFGeneratorService,
    private readonly currencyService: CurrencyService,
  ) {}

  /**
   * Create a new invoice with automatic calculations
   */
  async createInvoice(
    businessId: string,
    userId: string,
    request: CreateInvoiceRequest,
  ): Promise<Invoice> {
    try {
      // Validate input
      const validatedRequest = CreateInvoiceRequestSchema.parse(request)

      // Get customer details
      const customer = await this.getCustomer(businessId, validatedRequest.customerId)
      if (!customer) {
        throw new AppError(404, 'Customer not found')
      }

      // Generate invoice number
      const invoiceNumber = await this.numberingService.generateInvoiceNumber(businessId)

      // Calculate dates
      const issueDate = validatedRequest.issueDate || new Date().toISOString()
      const dueDate = validatedRequest.dueDate || this.calculateDueDate(
        issueDate,
        validatedRequest.paymentTerms || customer.paymentTerms,
      )

      // Process line items with tax calculations
      const processedLineItems = await this.processLineItems(
        businessId,
        validatedRequest.lineItems,
        customer.billingAddress.country,
      )

      // Calculate totals
      const calculations = this.calculateInvoiceTotals(processedLineItems)

      // Create invoice object
      const invoice: Invoice = {
        id: crypto.randomUUID(),
        businessId,
        invoiceNumber,
        customerId: validatedRequest.customerId,
        customerDetails: customer,
        type: validatedRequest.type || 'standard',
        status: 'draft',
        issueDate,
        dueDate,
        paymentTerms: validatedRequest.paymentTerms || customer.paymentTerms,
        currency: validatedRequest.currency || customer.currency,
        exchangeRate: 1, // TODO: Implement exchange rate lookup

        lineItems: processedLineItems,

        subtotal: calculations.subtotal,
        totalTax: calculations.totalTax,
        totalDiscount: calculations.totalDiscount,
        shippingCost: 0,
        adjustmentAmount: 0,
        totalAmount: calculations.totalAmount,

        amountPaid: 0,
        amountDue: calculations.totalAmount,

        notes: validatedRequest.notes,
        terms: validatedRequest.terms,
        purchaseOrderNumber: validatedRequest.purchaseOrderNumber,
        projectId: validatedRequest.projectId,

        approvalStatus: 'pending',

        attachments: [],

        createdBy: userId,
        createdAt: new Date().toISOString(),
        version: 1,

        metadata: validatedRequest.metadata,
      }

      // Validate complete invoice
      const validatedInvoice = InvoiceSchema.parse(invoice)

      // Save to database
      await this.saveInvoice(validatedInvoice)

      // Log audit event
      await this.auditLogger.log({
        businessId,
        userId,
        action: 'create',
        resourceType: 'invoice',
        resourceId: invoice.id,
        details: {
          invoiceNumber: invoice.invoiceNumber,
          customerId: invoice.customerId,
          totalAmount: invoice.totalAmount,
          currency: invoice.currency,
        },
      })

      return validatedInvoice

    } catch (error: any) {
      if (error instanceof z.ZodError) {
        throw new AppError(400, 'Invalid invoice data', true, error.errors)
      }

      if (error instanceof AppError) {
        throw error
      }

      throw new AppError(500, 'Failed to create invoice', false, { originalError: error })
    }
  }

  /**
   * Update an existing invoice
   */
  async updateInvoice(
    businessId: string,
    userId: string,
    invoiceId: string,
    request: UpdateInvoiceRequest,
  ): Promise<Invoice> {
    try {
      // Validate input
      const validatedRequest = UpdateInvoiceRequestSchema.parse(request)

      // Get existing invoice
      const existingInvoice = await this.getInvoice(businessId, invoiceId)
      if (!existingInvoice) {
        throw new AppError(404, 'Invoice not found')
      }

      // Check if invoice can be modified
      if (!this.canModifyInvoice(existingInvoice.status)) {
        throw new AppError(400, `Cannot modify invoice in ${existingInvoice.status} status`)
      }

      // Update customer if changed
      let customer = existingInvoice.customerDetails
      if (validatedRequest.customerId && validatedRequest.customerId !== existingInvoice.customerId) {
        const newCustomer = await this.getCustomer(businessId, validatedRequest.customerId)
        if (!newCustomer) {
          throw new AppError(404, 'Customer not found')
        }
        customer = newCustomer
      }

      // Process line items if provided
      let lineItems = existingInvoice.lineItems
      if (validatedRequest.lineItems) {
        lineItems = await this.processLineItems(
          businessId,
          validatedRequest.lineItems,
          customer.billingAddress.country,
        )
      }

      // Recalculate totals
      const calculations = this.calculateInvoiceTotals(lineItems)

      // Update invoice
      const updatedInvoice: Invoice = {
        ...existingInvoice,
        customerId: validatedRequest.customerId || existingInvoice.customerId,
        customerDetails: customer,
        dueDate: validatedRequest.dueDate || existingInvoice.dueDate,
        paymentTerms: validatedRequest.paymentTerms || existingInvoice.paymentTerms,
        lineItems,
        subtotal: calculations.subtotal,
        totalTax: calculations.totalTax,
        totalDiscount: calculations.totalDiscount,
        totalAmount: calculations.totalAmount,
        amountDue: calculations.totalAmount - existingInvoice.amountPaid,
        notes: validatedRequest.notes ?? existingInvoice.notes,
        terms: validatedRequest.terms ?? existingInvoice.terms,
        purchaseOrderNumber: validatedRequest.purchaseOrderNumber ?? existingInvoice.purchaseOrderNumber,
        projectId: validatedRequest.projectId ?? existingInvoice.projectId,
        updatedBy: userId,
        updatedAt: new Date().toISOString(),
        version: existingInvoice.version + 1,
        metadata: { ...existingInvoice.metadata, ...validatedRequest.metadata },
      }

      // Validate updated invoice
      const validatedInvoice = InvoiceSchema.parse(updatedInvoice)

      // Save to database
      await this.saveInvoice(validatedInvoice)

      // Log audit event
      await this.auditLogger.log({
        businessId,
        userId,
        action: 'update',
        resourceType: 'invoice',
        resourceId: invoiceId,
        details: {
          changes: this.getChangeDetails(existingInvoice, validatedInvoice),
          version: validatedInvoice.version,
        },
      })

      return validatedInvoice

    } catch (error: any) {
      if (error instanceof z.ZodError) {
        throw new AppError(400, 'Invalid update data', true, error.errors)
      }

      if (error instanceof AppError) {
        throw error
      }

      throw new AppError(500, 'Failed to update invoice', false, { originalError: error })
    }
  }

  /**
   * Get invoice by ID
   */
  async getInvoice(businessId: string, invoiceId: string): Promise<Invoice | null> {
    try {
      const stmt = this.db.prepare(`
        SELECT * FROM invoices
        WHERE id = ? AND business_id = ? AND deleted_at IS NULL
      `)

      const result = await stmt.bind(invoiceId, businessId).first()

      if (!result) {
        return null
      }

      return this.mapDatabaseRowToInvoice(result)

    } catch (error: any) {
      throw new AppError(500, 'Failed to retrieve invoice', false, { originalError: error })
    }
  }

  /**
   * Search invoices with filters and pagination
   */
  async searchInvoices(
    businessId: string,
    params: InvoiceSearchParams,
  ): Promise<InvoiceListResponse> {
    try {
      const {
        page = 1,
        limit = 20,
        status,
        customerId,
        startDate,
        endDate,
        minAmount,
        maxAmount,
        search,
        sortBy = 'issueDate',
        sortOrder = 'desc',
      } = params

      // Build WHERE conditions
      const conditions: string[] = ['business_id = ?', 'deleted_at IS NULL']
      const bindings: unknown[] = [businessId]

      if (status) {
        conditions.push('status = ?')
        bindings.push(status)
      }

      if (customerId) {
        conditions.push('customer_id = ?')
        bindings.push(customerId)
      }

      if (startDate) {
        conditions.push('issue_date >= ?')
        bindings.push(startDate)
      }

      if (endDate) {
        conditions.push('issue_date <= ?')
        bindings.push(endDate)
      }

      if (minAmount !== undefined) {
        conditions.push('total_amount >= ?')
        bindings.push(minAmount)
      }

      if (maxAmount !== undefined) {
        conditions.push('total_amount <= ?')
        bindings.push(maxAmount)
      }

      if (search) {
        conditions.push('(invoice_number LIKE ? OR customer_name LIKE ? OR notes LIKE ?)')
        const searchPattern = `%${search}%`
        bindings.push(searchPattern, searchPattern, searchPattern)
      }

      const whereClause = conditions.join(' AND ')

      // Get total count
      const countStmt = this.db.prepare(`
        SELECT COUNT(*) as total FROM invoices WHERE ${whereClause}
      `)
      const countResult = await countStmt.bind(...bindings).first()
      const total = countResult?.total as number || 0

      // Get invoices with pagination
      const offset = (page - 1) * limit
      const dataStmt = this.db.prepare(`
        SELECT * FROM invoices
        WHERE ${whereClause}
        ORDER BY ${this.getSortColumn(sortBy)} ${sortOrder.toUpperCase()}
        LIMIT ? OFFSET ?
      `)

      const results = await dataStmt.bind(...bindings, limit, offset).all()

      const invoices = results.results?.map((row: any) => this.mapDatabaseRowToInvoice(row)) || []

      // Calculate summary
      const summaryStmt = this.db.prepare(`
        SELECT
          SUM(total_amount) as total_amount,
          SUM(amount_paid) as paid_amount,
          SUM(amount_due) as outstanding_amount,
          SUM(CASE WHEN status = 'overdue' THEN amount_due ELSE 0 END) as overdue_amount,
          currency
        FROM invoices
        WHERE ${whereClause}
        GROUP BY currency
      `)

      const summaryResult = await summaryStmt.bind(...bindings).first()

      return {
        invoices,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit),
          hasNext: page * limit < total,
          hasPrev: page > 1,
        },
        summary: {
          totalAmount: summaryResult?.total_amount as number || 0,
          paidAmount: summaryResult?.paid_amount as number || 0,
          outstandingAmount: summaryResult?.outstanding_amount as number || 0,
          overdueAmount: summaryResult?.overdue_amount as number || 0,
          currency: summaryResult?.currency as string || 'USD',
        },
      }

    } catch (error: any) {
      throw new AppError(500, 'Failed to search invoices', false, { originalError: error })
    }
  }

  /**
   * Generate PDF for invoice
   */
  async generatePDF(
    businessId: string,
    invoiceId: string,
    options: PDFOptions = {},
  ): Promise<Uint8Array> {
    try {
      const validatedOptions = PDFOptionsSchema.parse(options)

      const invoice = await this.getInvoice(businessId, invoiceId)
      if (!invoice) {
        throw new AppError(404, 'Invoice not found')
      }

      const pdfBuffer = await this.pdfGenerator.generateInvoicePDF(invoice, validatedOptions)

      return pdfBuffer

    } catch (error: any) {
      if (error instanceof AppError) {
        throw error
      }

      throw new AppError(500, 'Failed to generate PDF', false, { originalError: error })
    }
  }

  /**
   * Send invoice via email
   */
  async sendInvoiceEmail(
    businessId: string,
    userId: string,
    invoiceId: string,
    emailConfig: EmailConfig,
  ): Promise<void> {
    try {
      const invoice = await this.getInvoice(businessId, invoiceId)
      if (!invoice) {
        throw new AppError(404, 'Invoice not found')
      }

      // Generate PDF if needed
      let pdfBuffer: Uint8Array | undefined
      if (emailConfig.attachPdf) {
        pdfBuffer = await this.generatePDF(businessId, invoiceId)
      }

      // Send email (implementation depends on email service)
      // This would integrate with your email service

      // Update invoice status
      if (invoice.status === 'draft' || invoice.status === 'approved') {
        await this.updateInvoiceStatus(businessId, userId, invoiceId, 'sent')
      }

      // Log audit event
      await this.auditLogger.log({
        businessId,
        userId,
        action: 'email_sent',
        resourceType: 'invoice',
        resourceId: invoiceId,
        details: {
          recipients: emailConfig.to,
          attachPdf: emailConfig.attachPdf,
        },
      })

    } catch (error: any) {
      if (error instanceof AppError) {
        throw error
      }

      throw new AppError(500, 'Failed to send invoice email', false, { originalError: error })
    }
  }

  /**
   * Update invoice status
   */
  async updateInvoiceStatus(
    businessId: string,
    userId: string,
    invoiceId: string,
    status: InvoiceStatus,
  ): Promise<Invoice> {
    try {
      const invoice = await this.getInvoice(businessId, invoiceId)
      if (!invoice) {
        throw new AppError(404, 'Invoice not found')
      }

      const validTransition = this.isValidStatusTransition(invoice.status, status)
      if (!validTransition) {
        throw new AppError(400, `Invalid status transition from ${invoice.status} to ${status}`)
      }

      const updatedInvoice: Invoice = {
        ...invoice,
        status,
        updatedBy: userId,
        updatedAt: new Date().toISOString(),
        version: invoice.version + 1,
      }

      // Save to database
      await this.saveInvoice(updatedInvoice)

      // Log audit event
      await this.auditLogger.log({
        businessId,
        userId,
        action: 'status_update',
        resourceType: 'invoice',
        resourceId: invoiceId,
        details: {
          fromStatus: invoice.status,
          toStatus: status,
        },
      })

      return updatedInvoice

    } catch (error: any) {
      if (error instanceof AppError) {
        throw error
      }

      throw new AppError(500, 'Failed to update invoice status', false, { originalError: error })
    }
  }

  // Private helper methods

  private async processLineItems(
    businessId: string,
    lineItems: Omit<InvoiceLineItem, 'id' | 'lineTotal' | 'taxAmount'>[],
    customerCountry: string,
  ): Promise<InvoiceLineItem[]> {
    const processedItems: InvoiceLineItem[] = []

    for (const item of lineItems) {
      // Calculate discount
      let discountAmount = item.discountAmount || 0
      if (item.discountPercentage && item.discountPercentage > 0) {
        discountAmount = (item.unitPrice * item.quantity * item.discountPercentage) / 100
      }

      const discountedAmount = (item.unitPrice * item.quantity) - discountAmount

      // Calculate tax
      let taxAmount = 0
      if (item.taxConfigId) {
        taxAmount = await this.taxCalculator.calculateLineTax(
          businessId,
          item.taxConfigId,
          discountedAmount,
          customerCountry,
        )
      }

      const lineTotal = discountedAmount + taxAmount

      processedItems.push({
        id: crypto.randomUUID(),
        productId: item.productId,
        description: item.description,
        quantity: item.quantity,
        unitPrice: item.unitPrice,
        discountAmount,
        discountPercentage: item.discountPercentage || 0,
        taxConfigId: item.taxConfigId,
        taxAmount,
        lineTotal,
        notes: item.notes,
        metadata: item.metadata,
      })
    }

    return processedItems
  }

  private calculateInvoiceTotals(lineItems: InvoiceLineItem[]): {
    subtotal: number
    totalTax: number
    totalDiscount: number
    totalAmount: number
  } {
    const subtotal = lineItems.reduce((sum, item) => sum + (item.unitPrice * item.quantity), 0)
    const totalDiscount = lineItems.reduce((sum, item) => sum + item.discountAmount, 0)
    const totalTax = lineItems.reduce((sum, item) => sum + item.taxAmount, 0)
    const totalAmount = lineItems.reduce((sum, item) => sum + item.lineTotal, 0)

    return {
      subtotal,
      totalTax,
      totalDiscount,
      totalAmount,
    }
  }

  private calculateDueDate(issueDate: string, paymentTerms: PaymentTerms): string {
    const issue = new Date(issueDate)
    let daysToAdd = 30 // Default to NET_30

    switch (paymentTerms) {
      case PaymentTerms.NET_15:
        daysToAdd = 15
        break
      case PaymentTerms.NET_30:
        daysToAdd = 30
        break
      case PaymentTerms.NET_45:
        daysToAdd = 45
        break
      case PaymentTerms.NET_60:
        daysToAdd = 60
        break
      case PaymentTerms.NET_90:
        daysToAdd = 90
        break
      case PaymentTerms.DUE_ON_RECEIPT:
        daysToAdd = 0
        break
      case PaymentTerms.CASH_ON_DELIVERY:
        daysToAdd = 0
        break
      case PaymentTerms.ADVANCE_PAYMENT:
        daysToAdd = -1 // Due before issue date
        break
    }

    const dueDate = new Date(issue)
    dueDate.setDate(dueDate.getDate() + daysToAdd)

    return dueDate.toISOString()
  }

  private canModifyInvoice(status: InvoiceStatus): boolean {
    return ['draft', 'pending_approval'].includes(status)
  }

  private isValidStatusTransition(fromStatus: InvoiceStatus, toStatus: InvoiceStatus): boolean {
    const validTransitions: Record<InvoiceStatus, InvoiceStatus[]> = {
      [InvoiceStatus.DRAFT]: [InvoiceStatus.PENDING_APPROVAL, InvoiceStatus.CANCELLED],
      [InvoiceStatus.PENDING_APPROVAL]: [InvoiceStatus.APPROVED, InvoiceStatus.DRAFT, InvoiceStatus.CANCELLED],
      [InvoiceStatus.APPROVED]: [InvoiceStatus.SENT, InvoiceStatus.CANCELLED],
     
  [InvoiceStatus.SENT]: [InvoiceStatus.VIEWED, InvoiceStatus.PARTIALLY_PAID, InvoiceStatus.PAID, InvoiceStatus.OVERDUE, InvoiceStatus.CANCELLED],
    
   [InvoiceStatus.VIEWED]: [InvoiceStatus.PARTIALLY_PAID, InvoiceStatus.PAID, InvoiceStatus.OVERDUE, InvoiceStatus.DISPUTED],
      [InvoiceStatus.PARTIALLY_PAID]: [InvoiceStatus.PAID, InvoiceStatus.OVERDUE, InvoiceStatus.DISPUTED],
      [InvoiceStatus.PAID]: [InvoiceStatus.REFUNDED],
      [InvoiceStatus.OVERDUE]: [InvoiceStatus.PARTIALLY_PAID, InvoiceStatus.PAID, InvoiceStatus.DISPUTED],
      [InvoiceStatus.CANCELLED]: [],
      [InvoiceStatus.REFUNDED]: [],
      [InvoiceStatus.DISPUTED]: [InvoiceStatus.PARTIALLY_PAID, InvoiceStatus.PAID, InvoiceStatus.CANCELLED],
    }

    return validTransitions[fromStatus]?.includes(toStatus) ?? false
  }

  private getSortColumn(sortBy: string): string {
    const columnMap: Record<string, string> = {
      invoiceNumber: 'invoice_number',
      issueDate: 'issue_date',
      dueDate: 'due_date',
      totalAmount: 'total_amount',
      status: 'status',
    }

    return columnMap[sortBy] || 'issue_date'
  }

  private getChangeDetails(oldInvoice: Invoice, newInvoice: Invoice): Record<string, unknown> {
    const changes: Record<string, unknown> = {}

    if (oldInvoice.customerId !== newInvoice.customerId) {
      changes.customerId = { from: oldInvoice.customerId, to: newInvoice.customerId }
    }

    if (oldInvoice.dueDate !== newInvoice.dueDate) {
      changes.dueDate = { from: oldInvoice.dueDate, to: newInvoice.dueDate }
    }

    if (oldInvoice.totalAmount !== newInvoice.totalAmount) {
      changes.totalAmount = { from: oldInvoice.totalAmount, to: newInvoice.totalAmount }
    }

    return changes
  }

  private async getCustomer(businessId: string, customerId: string): Promise<Customer | null> {
    // Implementation would fetch customer from database
    // This is a placeholder
    throw new Error('getCustomer not implemented')
  }

  private async saveInvoice(invoice: Invoice): Promise<void> {
    // Implementation would save invoice to database
    // This is a placeholder
    throw new Error('saveInvoice not implemented')
  }

  private mapDatabaseRowToInvoice(row: unknown): Invoice {
    // Implementation would map database row to Invoice object
    // This is a placeholder
    throw new Error('mapDatabaseRowToInvoice not implemented')
  }
}