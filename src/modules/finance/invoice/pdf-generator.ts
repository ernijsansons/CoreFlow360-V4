/**
 * PDF Generator Service
 * High-performance invoice PDF generation with template support
 */

import { Invoice, PDFOptions } from './types'
import { TaxCalculationEngine } from './tax-engine'
import { AppError } from '../../../shared/errors/app-error'
import { auditLogger } from '../../../shared/logging/audit-logger'

export interface PDFTemplate {
  id: string
  name: string
  layout: 'standard' | 'modern' | 'minimal' | 'corporate'
  colors: {
    primary: string
    secondary: string
    accent: string
    text: string
    background: string
  }
  fonts: {
    primary: string
    secondary: string
    monospace: string
  }
  logo?: {
    url: string
    width: number
    height: number
  }
  footer?: {
    text: string
    includePageNumbers: boolean
  }
}

export interface PDFGenerationContext {
  invoice: Invoice
  template: PDFTemplate
  options: PDFOptions
  businessInfo: {
    name: string
    address: string
    phone: string
    email: string
    website?: string
    taxId?: string
    logo?: string
  }
}

export // TODO: Consider splitting PDFGeneratorService into smaller, focused classes
class PDFGeneratorService {
  private taxEngine: TaxCalculationEngine

  constructor() {
    this.taxEngine = new TaxCalculationEngine()
  }

  async generateInvoicePDF(
    invoice: Invoice,
    options: PDFOptions = {},
    template?: PDFTemplate
  ): Promise<Buffer> {
    try {
      auditLogger.log({
        action: 'invoice_pdf_generation_started',
        invoiceId: invoice.id,
        userId: invoice.createdBy,
        metadata: { options, templateId: template?.id }
      })

      // Validate invoice data
      this.validateInvoiceForPDF(invoice)

      // Use default template if none provided
      const pdfTemplate = template || this.getDefaultTemplate()

      // Get business information
      const businessInfo = await this.getBusinessInfo(invoice.businessId)

      // Create PDF generation context
      const context: PDFGenerationContext = {
        invoice,
        template: pdfTemplate,
        options: {
          format: 'A4',
          orientation: 'portrait',
          includePaymentInstructions: true,
          includeTermsAndConditions: true,
          locale: 'en-US',
          ...options
        },
        businessInfo
      }

      // Generate PDF based on template
      const pdfBuffer = await this.renderPDF(context)

      auditLogger.log({
        action: 'invoice_pdf_generated',
        invoiceId: invoice.id,
        userId: invoice.createdBy,
        metadata: {
          size: pdfBuffer.length,
          format: context.options.format,
          template: pdfTemplate.name
        }
      })

      return pdfBuffer

    } catch (error: any) {
      auditLogger.log({
        action: 'invoice_pdf_generation_failed',
        invoiceId: invoice.id,
        userId: invoice.createdBy,
        error: error instanceof Error ? error.message : 'Unknown error'
      })

      throw new AppError(
        'PDF generation failed',
        'PDF_GENERATION_ERROR',
        500,
        { invoiceId: invoice.id, originalError: error }
      )
    }
  }

  private validateInvoiceForPDF(invoice: Invoice): void {
    if (!invoice.lineItems || invoice.lineItems.length === 0) {
      throw new AppError(
        'Invoice must have at least one line item',
        'INVALID_INVOICE_DATA',
        400
      )
    }

    if (!invoice.customerDetails) {
      throw new AppError(
        'Customer details are required for PDF generation',
        'MISSING_CUSTOMER_DATA',
        400
      )
    }

    if (invoice.totalAmount <= 0) {
      throw new AppError(
        'Invoice total must be greater than zero',
        'INVALID_INVOICE_AMOUNT',
        400
      )
    }
  }

  private async getBusinessInfo(businessId: string): Promise<PDFGenerationContext['businessInfo']> {
    // This would typically fetch from database
    // For now, return mock data
    return {
      name: 'CoreFlow360 Enterprise',
      address: '123 Business St\nSuite 100\nBusiness City, BC 12345\nUnited States',
      phone: '+1 (555) 123-4567',
      email: 'billing@coreflow360.com',
      website: 'www.coreflow360.com',
      taxId: '12-3456789'
    }
  }

  private getDefaultTemplate(): PDFTemplate {
    return {
      id: 'default-template',
      name: 'Professional',
      layout: 'standard',
      colors: {
        primary: '#2563eb',
        secondary: '#64748b',
        accent: '#059669',
        text: '#1e293b',
        background: '#ffffff'
      },
      fonts: {
        primary: 'Inter',
        secondary: 'Inter',
        monospace: 'JetBrains Mono'
      },
      footer: {
        text: 'Thank you for your business!',
        includePageNumbers: true
      }
    }
  }

  private async renderPDF(context: PDFGenerationContext): Promise<Buffer> {
    const { invoice, template, options, businessInfo } = context

    // Generate HTML content
    const htmlContent = this.generateHTMLContent(context)

    // Convert to PDF using puppeteer or similar
    const pdfBuffer = await this.convertHTMLToPDF(htmlContent, options)

    return pdfBuffer
  }

  private generateHTMLContent(context: PDFGenerationContext): string {
    const { invoice, template, businessInfo, options } = context

    // Calculate formatted amounts
    const formatter = new Intl.NumberFormat(options.locale, {
      style: 'currency',
      currency: invoice.currency
    })

    const formatAmount = (amount: number) => formatter.format(amount)

    // Generate line items HTML
    const lineItemsHTML = invoice.lineItems.map((item: any) => `
      <tr class="line-item">
        <td class="description">${this.escapeHTML(item.description)}</td>
        <td class="quantity">${item.quantity}</td>
        <td class="unit-price">${formatAmount(item.unitPrice)}</td>
        <td class="line-total">${formatAmount(item.lineTotal)}</td>
      </tr>
    `).join('')

    // Generate payment instructions if enabled
    const paymentInstructions = options.includePaymentInstructions ? `
      <div class="payment-instructions">
        <h3>Payment Instructions</h3>
        <p>Payment is due within ${this.getPaymentTermsDays(invoice.paymentTerms)} days of invoice date.</p>
        <p>Please reference invoice number ${invoice.invoiceNumber} with your payment.</p>
      </div>
    ` : ''

    // Generate terms and conditions if enabled
    const termsAndConditions = options.includeTermsAndConditions && invoice.terms ? `
      <div class="terms-conditions">
        <h3>Terms & Conditions</h3>
        <p>${this.escapeHTML(invoice.terms)}</p>
      </div>
    ` : ''

    return `
      <!DOCTYPE html>
      <html lang="${options.locale}">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Invoice ${invoice.invoiceNumber}</title>
        <style>
          ${this.generateCSS(template, options)}
        </style>
      </head>
      <body>
        <div class="invoice-container">
          <!-- Header -->
          <header class="invoice-header">
            <div class="business-info">
              <h1 class="business-name">${this.escapeHTML(businessInfo.name)}</h1>
              <div class="business-address">${this.formatAddress(businessInfo.address)}</div>
              <div class="business-contact">
                <div>Phone: ${businessInfo.phone}</div>
                <div>Email: ${businessInfo.email}</div>
                ${businessInfo.website ? `<div>Web: ${businessInfo.website}</div>` : ''}
              </div>
            </div>
            <div class="invoice-details">
              <h1 class="invoice-title">INVOICE</h1>
              <div class="invoice-meta">
                <div class="invoice-number">Invoice #: ${invoice.invoiceNumber}</div>
                <div class="invoice-date">Date: ${this.formatDate(invoice.issueDate)}</div>
                <div class="due-date">Due: ${this.formatDate(invoice.dueDate)}</div>
                <div class="invoice-status status-${invoice.status}">${this.formatStatus(invoice.status)}</div>
              </div>
            </div>
          </header>

          <!-- Customer Information -->
          <section class="customer-section">
            <div class="bill-to">
              <h3>Bill To:</h3>
              <div class="customer-name">${this.escapeHTML(invoice.customerDetails.name)}</div>
              <div class="customer-address">${this.formatCustomerAddress(invoice.customerDetails.billingAddress)}</div>
         
      ${invoice.customerDetails.email ? `<div class="customer-email">${invoice.customerDetails.email}</div>` : ''}
         
      ${invoice.customerDetails.phone ? `<div class="customer-phone">${invoice.customerDetails.phone}</div>` : ''}
            </div>
          </section>

          <!-- Line Items -->
          <section class="line-items-section">
            <table class="line-items-table">
              <thead>
                <tr>
                  <th class="description-header">Description</th>
                  <th class="quantity-header">Qty</th>
                  <th class="unit-price-header">Unit Price</th>
                  <th class="total-header">Total</th>
                </tr>
              </thead>
              <tbody>
                ${lineItemsHTML}
              </tbody>
            </table>
          </section>

          <!-- Totals -->
          <section class="totals-section">
            <div class="totals-table">
              <div class="total-row">
                <span class="total-label">Subtotal:</span>
                <span class="total-amount">${formatAmount(invoice.subtotal)}</span>
              </div>
              ${invoice.totalDiscount > 0 ? `
                <div class="total-row">
                  <span class="total-label">Discount:</span>
                  <span class="total-amount">-${formatAmount(invoice.totalDiscount)}</span>
                </div>
              ` : ''}
              ${invoice.shippingCost > 0 ? `
                <div class="total-row">
                  <span class="total-label">Shipping:</span>
                  <span class="total-amount">${formatAmount(invoice.shippingCost)}</span>
                </div>
              ` : ''}
              <div class="total-row">
                <span class="total-label">Tax:</span>
                <span class="total-amount">${formatAmount(invoice.totalTax)}</span>
              </div>
              ${invoice.adjustmentAmount !== 0 ? `
                <div class="total-row">
                  <span class="total-label">Adjustment:</span>
                  <span class="total-amount">${formatAmount(invoice.adjustmentAmount)}</span>
                </div>
              ` : ''}
              <div class="total-row grand-total">
                <span class="total-label">Total:</span>
                <span class="total-amount">${formatAmount(invoice.totalAmount)}</span>
              </div>
              ${invoice.amountPaid > 0 ? `
                <div class="total-row">
                  <span class="total-label">Amount Paid:</span>
                  <span class="total-amount">-${formatAmount(invoice.amountPaid)}</span>
                </div>
                <div class="total-row amount-due">
                  <span class="total-label">Amount Due:</span>
                  <span class="total-amount">${formatAmount(invoice.amountDue)}</span>
                </div>
              ` : ''}
            </div>
          </section>

          <!-- Notes -->
          ${invoice.notes ? `
            <section class="notes-section">
              <h3>Notes</h3>
              <p>${this.escapeHTML(invoice.notes)}</p>
            </section>
          ` : ''}

          <!-- Payment Instructions -->
          ${paymentInstructions}

          <!-- Terms & Conditions -->
          ${termsAndConditions}

          <!-- Footer -->
          <footer class="invoice-footer">
            ${template.footer ? `
              <div class="footer-text">${this.escapeHTML(template.footer.text)}</div>
            ` : ''}
            ${template.footer?.includePageNumbers ? '<div class="page-numbers">Page 1 of 1</div>' : ''}
          </footer>
        </div>
      </body>
      </html>
    `
  }

  private generateCSS(template: PDFTemplate, options: PDFOptions): string {
    return `
      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
      }

      body {
        font-family: ${template.fonts.primary}, sans-serif;
        font-size: 12px;
        line-height: 1.4;
        color: ${template.colors.text};
        background-color: ${template.colors.background};
      }

      .invoice-container {
        max-width: 210mm;
        margin: 0 auto;
        padding: 20mm;
      }

      .invoice-header {
        display: flex;
        justify-content: space-between;
        margin-bottom: 30px;
        padding-bottom: 20px;
        border-bottom: 2px solid ${template.colors.primary};
      }

      .business-name {
        font-size: 24px;
        font-weight: bold;
        color: ${template.colors.primary};
        margin-bottom: 10px;
      }

      .business-address {
        margin-bottom: 10px;
        white-space: pre-line;
      }

      .business-contact div {
        margin-bottom: 2px;
      }

      .invoice-title {
        font-size: 32px;
        font-weight: bold;
        color: ${template.colors.primary};
        text-align: right;
        margin-bottom: 15px;
      }

      .invoice-meta {
        text-align: right;
      }

      .invoice-meta > div {
        margin-bottom: 5px;
      }

      .invoice-status {
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: bold;
        text-transform: uppercase;
        font-size: 10px;
      }

      .status-draft { background-color: #fbbf24; color: #78350f; }
      .status-sent { background-color: #3b82f6; color: white; }
      .status-paid { background-color: ${template.colors.accent}; color: white; }
      .status-overdue { background-color: #ef4444; color: white; }

      .customer-section {
        margin-bottom: 30px;
      }

      .bill-to h3 {
        font-size: 14px;
        font-weight: bold;
        margin-bottom: 10px;
        color: ${template.colors.primary};
      }

      .customer-name {
        font-weight: bold;
        margin-bottom: 5px;
      }

      .line-items-table {
        width: 100%;
        border-collapse: collapse;
        margin-bottom: 20px;
      }

      .line-items-table th {
        background-color: ${template.colors.primary};
        color: white;
        padding: 12px 8px;
        text-align: left;
        font-weight: bold;
      }

      .line-items-table td {
        padding: 10px 8px;
        border-bottom: 1px solid #e5e7eb;
      }

      .line-items-table .quantity,
      .line-items-table .unit-price,
      .line-items-table .line-total,
      .quantity-header,
      .unit-price-header,
      .total-header {
        text-align: right;
      }

      .totals-section {
        margin-top: 20px;
      }

      .totals-table {
        margin-left: auto;
        width: 300px;
      }

      .total-row {
        display: flex;
        justify-content: space-between;
        padding: 8px 0;
        border-bottom: 1px solid #e5e7eb;
      }

      .grand-total {
        font-weight: bold;
        font-size: 16px;
        border-top: 2px solid ${template.colors.primary};
        border-bottom: 2px solid ${template.colors.primary};
        color: ${template.colors.primary};
      }

      .amount-due {
        font-weight: bold;
        color: #ef4444;
      }

      .notes-section,
      .payment-instructions,
      .terms-conditions {
        margin-top: 30px;
      }

      .notes-section h3,
      .payment-instructions h3,
      .terms-conditions h3 {
        font-size: 14px;
        font-weight: bold;
        margin-bottom: 10px;
        color: ${template.colors.primary};
      }

      .invoice-footer {
        margin-top: 40px;
        padding-top: 20px;
        border-top: 1px solid #e5e7eb;
        text-align: center;
        color: ${template.colors.secondary};
        font-size: 10px;
      }

      @media print {
        .invoice-container {
          margin: 0;
          padding: 15mm;
        }
      }
    `
  }

  private async convertHTMLToPDF(html: string, options: PDFOptions): Promise<Buffer> {
    // This would typically use puppeteer or similar PDF generation library
    // For now, return a mock buffer
    const mockPDFContent =
  `Mock PDF content for invoice\nOptions: ${JSON.stringify(options)}\nHTML length: ${html.length}`
    return Buffer.from(mockPDFContent, 'utf8')
  }

  private escapeHTML(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
  }

  private formatAddress(address: string): string {
    return address.replace(/\n/g, '<br>')
  }

  private formatCustomerAddress(address: any): string {
    return `${address.street}<br>${address.city}, ${address.state} ${address.postalCode}<br>${address.country}`
  }

  private formatDate(dateString: string): string {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    })
  }

  private formatStatus(status: string): string {
    return status.replace(/_/g, ' ')
  }

  private getPaymentTermsDays(terms: string): number {
    const match = terms.match(/(\d+)/)
    return match ? parseInt(match[1]) : 30
  }
}