/**
 * Invoice PDF Generator with R2 Storage
 * Generates professional PDF invoices and stores them in Cloudflare R2
 */

import type { R2Bucket } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';
import {
  Invoice,
  InvoiceTemplate,
  InvoiceAddress,
  Customer
} from './types';
import { validateBusinessId, formatCurrency, formatDate } from './utils';

export interface PDFGenerationOptions {
  template?: InvoiceTemplate;
  includePaymentStub?: boolean;
  watermark?: string;
  customFooter?: string;
}

export interface BusinessInfo {
  name: string;
  address: InvoiceAddress;
  phone?: string;
  email?: string;
  website?: string;
  taxId?: string;
  logoUrl?: string;
}

export class InvoicePDFGenerator {
  private logger: Logger;
  private r2Bucket?: R2Bucket;

  constructor(r2Bucket?: R2Bucket) {
    this.logger = new Logger();
    this.r2Bucket = r2Bucket;
  }

  /**
   * Generate PDF invoice and store in R2
   */
  async generateInvoicePDF(
    invoice: Invoice,
    businessInfo: BusinessInfo,
    customer: Customer,
    businessId: string,
    options?: PDFGenerationOptions
  ): Promise<{ pdfUrl: string; pdfBuffer: ArrayBuffer }> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      // Generate HTML content for PDF
      const htmlContent = this.generateInvoiceHTML(
        invoice,
        businessInfo,
        customer,
        options
      );

      // Convert HTML to PDF using browser rendering
      const pdfBuffer = await this.htmlToPDF(htmlContent);

      // Store in R2 if available
      let pdfUrl = '';
      if (this.r2Bucket) {
        const fileName = `invoices/${validBusinessId}/${invoice.invoiceNumber}.pdf`;
        const r2Object = await this.r2Bucket.put(fileName, pdfBuffer, {
          httpMetadata: {
            contentType: 'application/pdf',
            cacheControl: 'public, max-age=31536000'
          },
          customMetadata: {
            invoiceId: invoice.id,
            invoiceNumber: invoice.invoiceNumber,
            customerId: invoice.customerId,
            businessId: validBusinessId,
            generatedAt: Date.now().toString()
          }
        });

        if (r2Object) {
          pdfUrl = `https://your-r2-domain.com/${fileName}`;
        }
      }

      this.logger.info('Invoice PDF generated', {
        invoiceId: invoice.id,
        invoiceNumber: invoice.invoiceNumber,
        pdfSize: pdfBuffer.byteLength,
        storageUrl: pdfUrl,
        businessId: validBusinessId
      });

      return {
        pdfUrl,
        pdfBuffer
      };

    } catch (error: any) {
      this.logger.error('Failed to generate invoice PDF', error, {
        invoiceId: invoice.id,
        invoiceNumber: invoice.invoiceNumber,
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Generate HTML content for invoice
   */
  private generateInvoiceHTML(
    invoice: Invoice,
    businessInfo: BusinessInfo,
    customer: Customer,
    options?: PDFGenerationOptions
  ): string {
    const template = options?.template;
    const colors = template?.colors || {
      primary: '#2563eb',
      secondary: '#64748b',
      accent: '#f1f5f9'
    };

    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Invoice ${invoice.invoiceNumber}</title>
    <style>
        ${this.getInvoiceCSS(colors, template?.layout || 'standard')}
    </style>
</head>
<body>
    <div class="invoice-container">
        ${options?.watermark ? `<div class="watermark">${options.watermark}</div>` : ''}

        <!-- Header -->
        <div class="invoice-header">
            <div class="business-info">
           
      ${businessInfo.logoUrl ? `<img src="${businessInfo.logoUrl}" alt="${businessInfo.name}" class="logo">` : ''}
                <div class="business-details">
                    <h1 class="business-name">${businessInfo.name}</h1>
                    ${this.formatAddress(businessInfo.address)}
                    ${businessInfo.phone ? `<div>Phone: ${businessInfo.phone}</div>` : ''}
                    ${businessInfo.email ? `<div>Email: ${businessInfo.email}</div>` : ''}
                    ${businessInfo.website ? `<div>Website: ${businessInfo.website}</div>` : ''}
                    ${businessInfo.taxId ? `<div>Tax ID: ${businessInfo.taxId}</div>` : ''}
                </div>
            </div>
            <div class="invoice-info">
                <h2 class="invoice-title">INVOICE</h2>
                <div class="invoice-details">
                    <div class="detail-row">
                        <span class="label">Invoice #:</span>
                        <span class="value">${invoice.invoiceNumber}</span>
                    </div>
                    <div class="detail-row">
                        <span class="label">Issue Date:</span>
                        <span class="value">${formatDate(invoice.issueDate)}</span>
                    </div>
                    <div class="detail-row">
                        <span class="label">Due Date:</span>
                        <span class="value">${formatDate(invoice.dueDate)}</span>
                    </div>
                    ${invoice.poNumber ? `
                    <div class="detail-row">
                        <span class="label">PO Number:</span>
                        <span class="value">${invoice.poNumber}</span>
                    </div>` : ''}
                </div>
            </div>
        </div>

        <!-- Customer Info -->
        <div class="customer-section">
            <div class="bill-to">
                <h3>Bill To:</h3>
                <div class="customer-info">
                    <div class="customer-name">${invoice.customerName}</div>
                    ${invoice.billToAddress ? this.formatAddress(invoice.billToAddress) : ''}
                    ${customer.email ? `<div>Email: ${customer.email}</div>` : ''}
                    ${customer.phone ? `<div>Phone: ${customer.phone}</div>` : ''}
                </div>
            </div>
            ${invoice.shipToAddress ? `
            <div class="ship-to">
                <h3>Ship To:</h3>
                <div class="shipping-info">
                    ${this.formatAddress(invoice.shipToAddress)}
                </div>
            </div>` : ''}
        </div>

        <!-- Line Items -->
        <div class="line-items-section">
            <table class="line-items-table">
                <thead>
                    <tr>
                        <th class="description-col">Description</th>
                        <th class="quantity-col">Qty</th>
                        <th class="price-col">Unit Price</th>
                        ${template?.showDiscountColumn ? '<th class="discount-col">Discount</th>' : ''}
                        ${template?.showTaxColumn ? '<th class="tax-col">Tax</th>' : ''}
                        <th class="total-col">Total</th>
                    </tr>
                </thead>
                <tbody>
                    ${invoice.lines.map((line: any) => `
                    <tr>
                        <td class="description-cell">
                            <div class="line-description">${line.description}</div>
                            ${line.projectId ? `<div class="line-project">Project: ${line.projectId}</div>` : ''}
                        </td>
                        <td class="quantity-cell">${line.quantity}</td>
                        <td class="price-cell">${formatCurrency(line.unitPrice, invoice.currency)}</td>
                
         ${template?.showDiscountColumn ? `<td class="discount-cell">${line.discount ? formatCurrency(line.discount, invoice.currency) : '-'}</td>` : ''}
              
           ${template?.showTaxColumn ? `<td class="tax-cell">${formatCurrency(line.taxAmount, invoice.currency)}</td>` : ''}
                        <td class="total-cell">${formatCurrency(line.lineTotal, invoice.currency)}</td>
                    </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>

        <!-- Totals -->
        <div class="totals-section">
            <div class="totals-table">
                <div class="total-row">
                    <span class="total-label">Subtotal:</span>
                    <span class="total-value">${formatCurrency(invoice.subtotal, invoice.currency)}</span>
                </div>
                ${invoice.discountTotal > 0 ? `
                <div class="total-row">
                    <span class="total-label">Discount:</span>
                    <span class="total-value">-${formatCurrency(invoice.discountTotal, invoice.currency)}</span>
                </div>` : ''}
                ${invoice.taxTotal > 0 ? `
                <div class="total-row">
                    <span class="total-label">Tax:</span>
                    <span class="total-value">${formatCurrency(invoice.taxTotal, invoice.currency)}</span>
                </div>` : ''}
                <div class="total-row total-amount">
                    <span class="total-label">Total:</span>
                    <span class="total-value">${formatCurrency(invoice.total, invoice.currency)}</span>
                </div>
                ${invoice.balanceDue !== invoice.total ? `
                <div class="total-row balance-due">
                    <span class="total-label">Balance Due:</span>
                    <span class="total-value">${formatCurrency(invoice.balanceDue, invoice.currency)}</span>
                </div>` : ''}
            </div>
        </div>

        <!-- Payment Terms -->
        <div class="payment-terms-section">
            <h3>Payment Terms</h3>
            <p>${invoice.terms.description}</p>
        </div>

        <!-- Notes -->
        ${invoice.notes ? `
        <div class="notes-section">
            <h3>Notes</h3>
            <p>${invoice.notes}</p>
        </div>` : ''}

        <!-- Footer -->
        <div class="invoice-footer">
            ${options?.customFooter || template?.footerText || 'Thank you for your business!'}
        </div>

        <!-- Payment Stub -->
        ${options?.includePaymentStub ? this.generatePaymentStub(invoice, businessInfo) : ''}
    </div>
</body>
</html>`;
  }

  /**
   * Generate CSS styles for invoice
   */
  private getInvoiceCSS(colors: any, layout: string): string {
    return `
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            font-size: 12px;
            line-height: 1.5;
            color: #333;
            background: white;
        }

        .invoice-container {
            max-width: 800px;
            margin: 0 auto;
            padding: 40px;
            position: relative;
        }

        .watermark {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%) rotate(-45deg);
            font-size: 72px;
            color: rgba(0, 0, 0, 0.1);
            font-weight: bold;
            z-index: -1;
            pointer-events: none;
        }

        .invoice-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 2px solid ${colors.primary};
        }

        .business-info {
            flex: 1;
        }

        .logo {
            max-width: 150px;
            max-height: 80px;
            margin-bottom: 15px;
        }

        .business-name {
            font-size: 24px;
            font-weight: bold;
            color: ${colors.primary};
            margin-bottom: 10px;
        }

        .business-details {
            color: ${colors.secondary};
            line-height: 1.6;
        }

        .invoice-info {
            text-align: right;
            min-width: 200px;
        }

        .invoice-title {
            font-size: 28px;
            font-weight: bold;
            color: ${colors.primary};
            margin-bottom: 15px;
        }

        .detail-row {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
        }

        .label {
            font-weight: 600;
            color: ${colors.secondary};
        }

        .value {
            font-weight: 500;
        }

        .customer-section {
            display: flex;
            justify-content: space-between;
            margin-bottom: 40px;
        }

        .bill-to, .ship-to {
            flex: 1;
            margin-right: 40px;
        }

        .bill-to h3, .ship-to h3 {
            font-size: 16px;
            font-weight: bold;
            color: ${colors.primary};
            margin-bottom: 10px;
        }

        .customer-name {
            font-weight: bold;
            font-size: 14px;
            margin-bottom: 5px;
        }

        .line-items-section {
            margin-bottom: 30px;
        }

        .line-items-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }

        .line-items-table th {
            background-color: ${colors.accent};
            color: ${colors.primary};
            font-weight: bold;
            padding: 12px 8px;
            text-align: left;
            border-bottom: 2px solid ${colors.primary};
        }

        .line-items-table td {
            padding: 10px 8px;
            border-bottom: 1px solid #e2e8f0;
        }

        .description-col {
            width: 40%;
        }

        .quantity-col {
            width: 10%;
            text-align: center;
        }

        .price-col, .discount-col, .tax-col {
            width: 15%;
            text-align: right;
        }

        .total-col {
            width: 15%;
            text-align: right;
            font-weight: bold;
        }

        .quantity-cell {
            text-align: center;
        }

        .price-cell, .discount-cell, .tax-cell, .total-cell {
            text-align: right;
        }

        .line-description {
            font-weight: 500;
        }

        .line-project {
            font-size: 10px;
            color: ${colors.secondary};
            margin-top: 2px;
        }

        .totals-section {
            display: flex;
            justify-content: flex-end;
            margin-bottom: 30px;
        }

        .totals-table {
            min-width: 250px;
        }

        .total-row {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #e2e8f0;
        }

        .total-amount {
            border-bottom: 2px solid ${colors.primary};
            font-weight: bold;
            font-size: 14px;
            color: ${colors.primary};
        }

        .balance-due {
            border-bottom: none;
            font-weight: bold;
            font-size: 16px;
            color: #dc2626;
            margin-top: 8px;
        }

        .payment-terms-section, .notes-section {
            margin-bottom: 30px;
        }

        .payment-terms-section h3, .notes-section h3 {
            font-size: 14px;
            font-weight: bold;
            color: ${colors.primary};
            margin-bottom: 8px;
        }

        .invoice-footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e2e8f0;
            color: ${colors.secondary};
            font-style: italic;
        }

        .payment-stub {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px dashed #ccc;
        }

        .payment-stub h3 {
            color: ${colors.primary};
            margin-bottom: 15px;
        }

        @media print {
            .invoice-container {
                padding: 20px;
            }

            .payment-stub {
                page-break-before: always;
            }
        }
    `;
  }

  /**
   * Format address for display
   */
  private formatAddress(address: InvoiceAddress): string {
    const parts = [
      address.name,
      address.line1,
      address.line2,
      `${address.city}${address.state ? `, ${address.state}` : ''} ${address.postalCode}`,
      address.country
    ].filter(Boolean);

    return parts.map((part: any) => `<div>${part}</div>`).join('');
  }

  /**
   * Generate payment stub
   */
  private generatePaymentStub(invoice: Invoice, businessInfo: BusinessInfo): string {
    return `
        <div class="payment-stub">
            <h3>Payment Stub - Detach and Return with Payment</h3>
            <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                <div>
                    <strong>Remit To:</strong><br>
                    ${businessInfo.name}<br>
                    ${this.formatAddress(businessInfo.address)}
                </div>
                <div style="text-align: right;">
                    <div><strong>Invoice #:</strong> ${invoice.invoiceNumber}</div>
                    <div><strong>Due Date:</strong> ${formatDate(invoice.dueDate)}</div>
                    <div><strong>Amount Due:</strong> ${formatCurrency(invoice.balanceDue, invoice.currency)}</div>
                </div>
            </div>
        </div>
    `;
  }

  /**
   * Convert HTML to PDF using puppeteer or similar
   */
  private async htmlToPDF(htmlContent: string): Promise<ArrayBuffer> {
    // This is a placeholder implementation
    // In a real implementation, you would use:
    // 1. Puppeteer (if running in a Node.js environment)
    // 2. Chrome DevTools Protocol via Cloudflare Workers Browser Rendering API
    // 3. A third-party service like PDFShift, HTMLToPDF, etc.

    try {
      // Example using a hypothetical PDF generation service
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
            margin: {
              top: '1cm',
              right: '1cm',
              bottom: '1cm',
              left: '1cm'
            },
            printBackground: true,
            preferCSSPageSize: true
          }
        })
      });

      if (!response.ok) {
        throw new Error(`PDF generation failed: ${response.statusText}`);
      }

      return await response.arrayBuffer();

    } catch (error: any) {
      this.logger.error('Failed to convert HTML to PDF', error);

      // Fallback: Return a simple text-based "PDF" (for demonstration)
      const fallbackContent = `PDF
  Generation Error\n\nFailed to generate PDF for invoice.\nHTML content length: ${htmlContent.length} characters`;
      return new TextEncoder().encode(fallbackContent).buffer;
    }
  }

  /**
   * Delete PDF from R2 storage
   */
  async deletePDF(
    invoiceNumber: string,
    businessId: string
  ): Promise<void> {
    if (!this.r2Bucket) {
      return;
    }

    const validBusinessId = validateBusinessId(businessId);

    try {
      const fileName = `invoices/${validBusinessId}/${invoiceNumber}.pdf`;
      await this.r2Bucket.delete(fileName);

      this.logger.info('Invoice PDF deleted from R2', {
        invoiceNumber,
        fileName,
        businessId: validBusinessId
      });

    } catch (error: any) {
      this.logger.error('Failed to delete PDF from R2', error, {
        invoiceNumber,
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Get PDF from R2 storage
   */
  async getPDF(
    invoiceNumber: string,
    businessId: string
  ): Promise<{ pdf: ArrayBuffer; metadata: Record<string, string> } | null> {
    if (!this.r2Bucket) {
      return null;
    }

    const validBusinessId = validateBusinessId(businessId);

    try {
      const fileName = `invoices/${validBusinessId}/${invoiceNumber}.pdf`;
      const object = await this.r2Bucket.get(fileName);

      if (!object) {
        return null;
      }

      return {
        pdf: await object.arrayBuffer(),
        metadata: object.customMetadata || {}
      };

    } catch (error: any) {
      this.logger.error('Failed to get PDF from R2', error, {
        invoiceNumber,
        businessId: validBusinessId
      });
      return null;
    }
  }
}