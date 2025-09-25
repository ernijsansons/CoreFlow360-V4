/**
 * Invoice Email Manager
 * Handles email delivery of invoices via Cloudflare Email
 */
import { Logger } from '../../shared/logger';
import { InvoicePDFGenerator, BusinessInfo } from './invoice-pdf-generator';
import {
  Invoice,
  Customer,
  SendInvoiceRequest,
  InvoiceStatus,
  InvoiceTemplate
} from './types';
import { validateBusinessId, formatCurrency, formatDate } from './utils';

export interface EmailConfiguration {
  fromName: string;
  fromEmail: string;
  replyToEmail?: string;
  smtpSettings?: {
    host: string;
    port: number;
    username: string;
    password: string;
    secure: boolean;
  };
}

export interface EmailTemplate {
  subject: string;
  htmlBody: string;
  textBody: string;
}

export interface EmailDeliveryResult {
  messageId: string;
  status: 'sent' | 'failed' | 'queued';
  deliveredAt?: number;
  errorMessage?: string;
}

export // TODO: Consider splitting InvoiceEmailManager into smaller, focused classes
class InvoiceEmailManager {
  private logger: Logger;
  private pdfGenerator?: InvoicePDFGenerator;

  constructor(pdfGenerator?: InvoicePDFGenerator) {
    this.logger = new Logger();
    this.pdfGenerator = pdfGenerator;
  }

  /**
   * Send invoice via email
   */
  async sendInvoice(
    request: SendInvoiceRequest,
    configuration: EmailConfiguration
  ): Promise<EmailDeliveryResult> {
    try {
      this.logger.info('Starting invoice email delivery', {
        invoiceId: request.invoiceId,
        customerEmail: request.customerEmail,
        businessId: request.businessId
      });

      // Validate request
      this.validateSendRequest(request);

      // Get invoice data
      const invoice = await this.getInvoiceData(request.invoiceId, request.businessId);
      if (!invoice) {
        throw new Error('Invoice not found');
      }

      // Get customer data
      const customer = await this.getCustomerData(request.customerId, request.businessId);
      if (!customer) {
        throw new Error('Customer not found');
      }

      // Generate PDF if requested
      let pdfAttachment: Uint8Array | null = null;
      if (request.includePDF && this.pdfGenerator) {
        pdfAttachment = await this.generateInvoicePDF(invoice, customer, request.businessId);
      }

      // Generate email template
      const template = await this.generateEmailTemplate(
        invoice,
        customer,
        request.templateId,
        request.businessId
      );

      // Send email
      const result = await this.deliverEmail({
        to: request.customerEmail,
        from: configuration.fromEmail,
        fromName: configuration.fromName,
        replyTo: configuration.replyToEmail,
        subject: template.subject,
        htmlBody: template.htmlBody,
        textBody: template.textBody,
        attachments: pdfAttachment ? [{
          filename: `invoice-${invoice.invoiceNumber}.pdf`,
          content: pdfAttachment,
          contentType: 'application/pdf'
        }] : undefined
      });

      // Update invoice status
      await this.updateInvoiceStatus(request.invoiceId, 'sent', result.messageId);

      this.logger.info('Invoice email sent successfully', {
        invoiceId: request.invoiceId,
        messageId: result.messageId,
        customerEmail: request.customerEmail
      });

      return result;

    } catch (error) {
      this.logger.error('Failed to send invoice email', {
        error: error instanceof Error ? error.message : 'Unknown error',
        invoiceId: request.invoiceId,
        customerEmail: request.customerEmail
      });

      // Update invoice status to failed
      await this.updateInvoiceStatus(request.invoiceId, 'failed', undefined, error instanceof Error ? error.message : 'Unknown error');

      return {
        messageId: '',
        status: 'failed',
        errorMessage: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  /**
   * Send invoice reminder
   */
  async sendReminder(
    invoiceId: string,
    businessId: string,
    configuration: EmailConfiguration
  ): Promise<EmailDeliveryResult> {
    try {
      this.logger.info('Sending invoice reminder', {
        invoiceId,
        businessId
      });

      // Get invoice data
      const invoice = await this.getInvoiceData(invoiceId, businessId);
      if (!invoice) {
        throw new Error('Invoice not found');
      }

      // Get customer data
      const customer = await this.getCustomerData(invoice.customerId, businessId);
      if (!customer) {
        throw new Error('Customer not found');
      }

      // Generate reminder template
      const template = await this.generateReminderTemplate(invoice, customer, businessId);

      // Send email
      const result = await this.deliverEmail({
        to: customer.email,
        from: configuration.fromEmail,
        fromName: configuration.fromName,
        replyTo: configuration.replyToEmail,
        subject: template.subject,
        htmlBody: template.htmlBody,
        textBody: template.textBody
      });

      // Update reminder count
      await this.updateReminderCount(invoiceId);

      this.logger.info('Invoice reminder sent successfully', {
        invoiceId,
        messageId: result.messageId,
        customerEmail: customer.email
      });

      return result;

    } catch (error) {
      this.logger.error('Failed to send invoice reminder', {
        error: error instanceof Error ? error.message : 'Unknown error',
        invoiceId
      });

      return {
        messageId: '',
        status: 'failed',
        errorMessage: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  /**
   * Send payment confirmation
   */
  async sendPaymentConfirmation(
    invoiceId: string,
    businessId: string,
    paymentAmount: number,
    paymentMethod: string,
    configuration: EmailConfiguration
  ): Promise<EmailDeliveryResult> {
    try {
      this.logger.info('Sending payment confirmation', {
        invoiceId,
        businessId,
        paymentAmount,
        paymentMethod
      });

      // Get invoice data
      const invoice = await this.getInvoiceData(invoiceId, businessId);
      if (!invoice) {
        throw new Error('Invoice not found');
      }

      // Get customer data
      const customer = await this.getCustomerData(invoice.customerId, businessId);
      if (!customer) {
        throw new Error('Customer not found');
      }

      // Generate payment confirmation template
      const template = await this.generatePaymentConfirmationTemplate(
        invoice,
        customer,
        paymentAmount,
        paymentMethod,
        businessId
      );

      // Send email
      const result = await this.deliverEmail({
        to: customer.email,
        from: configuration.fromEmail,
        fromName: configuration.fromName,
        replyTo: configuration.replyToEmail,
        subject: template.subject,
        htmlBody: template.htmlBody,
        textBody: template.textBody
      });

      this.logger.info('Payment confirmation sent successfully', {
        invoiceId,
        messageId: result.messageId,
        customerEmail: customer.email
      });

      return result;

    } catch (error) {
      this.logger.error('Failed to send payment confirmation', {
        error: error instanceof Error ? error.message : 'Unknown error',
        invoiceId
      });

      return {
        messageId: '',
        status: 'failed',
        errorMessage: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  /**
   * Get email delivery status
   */
  async getDeliveryStatus(messageId: string): Promise<{
    status: 'sent' | 'delivered' | 'failed' | 'bounced' | 'unknown';
    deliveredAt?: number;
    errorMessage?: string;
  }> {
    try {
      // This would typically query an email service API
      // For now, we'll return a mock response
      return {
        status: 'delivered',
        deliveredAt: Date.now()
      };
    } catch (error) {
      this.logger.error('Failed to get delivery status', {
        error: error instanceof Error ? error.message : 'Unknown error',
        messageId
      });

      return {
        status: 'unknown',
        errorMessage: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  /**
   * Get email templates
   */
  async getEmailTemplates(businessId: string): Promise<InvoiceTemplate[]> {
    try {
      // This would typically query a database
      // For now, we'll return mock templates
      return [
        {
          id: 'default',
          name: 'Default Invoice Template',
          subject: 'Invoice {{invoiceNumber}} from {{businessName}}',
          htmlBody: this.getDefaultHTMLTemplate(),
          textBody: this.getDefaultTextTemplate(),
          isDefault: true
        },
        {
          id: 'reminder',
          name: 'Payment Reminder Template',
          subject: 'Payment Reminder - Invoice {{invoiceNumber}}',
          htmlBody: this.getReminderHTMLTemplate(),
          textBody: this.getReminderTextTemplate(),
          isDefault: false
        }
      ];
    } catch (error) {
      this.logger.error('Failed to get email templates', {
        error: error instanceof Error ? error.message : 'Unknown error',
        businessId
      });
      return [];
    }
  }

  /**
   * Update email template
   */
  async updateEmailTemplate(
    templateId: string,
    template: Partial<InvoiceTemplate>,
    businessId: string
  ): Promise<boolean> {
    try {
      // This would typically update a database
      this.logger.info('Email template updated', {
        templateId,
        businessId
      });
      return true;
    } catch (error) {
      this.logger.error('Failed to update email template', {
        error: error instanceof Error ? error.message : 'Unknown error',
        templateId,
        businessId
      });
      return false;
    }
  }

  private validateSendRequest(request: SendInvoiceRequest): void {
    if (!request.invoiceId) {
      throw new Error('Invoice ID is required');
    }
    if (!request.customerEmail) {
      throw new Error('Customer email is required');
    }
    if (!request.businessId) {
      throw new Error('Business ID is required');
    }
    if (!validateBusinessId(request.businessId)) {
      throw new Error('Invalid business ID');
    }
  }

  private async getInvoiceData(invoiceId: string, businessId: string): Promise<Invoice | null> {
    // This would typically query a database
    // For now, we'll return mock data
    return {
      id: invoiceId,
      invoiceNumber: 'INV-123456',
      customerId: 'cust_123',
      businessId,
      status: 'draft' as InvoiceStatus,
      subtotal: 1000.00,
      taxAmount: 100.00,
      totalAmount: 1100.00,
      dueDate: new Date('2024-12-31'),
      createdAt: new Date(),
      updatedAt: new Date()
    };
  }

  private async getCustomerData(customerId: string, businessId: string): Promise<Customer | null> {
    // This would typically query a database
    // For now, we'll return mock data
    return {
      id: customerId,
      businessId,
      name: 'John Doe',
      email: 'john.doe@example.com',
      phone: '+1-555-0123',
      address: {
        street: '123 Main St',
        city: 'Anytown',
        state: 'CA',
        zipCode: '12345',
        country: 'US'
      },
      createdAt: new Date(),
      updatedAt: new Date()
    };
  }

  private async generateInvoicePDF(
    invoice: Invoice,
    customer: Customer,
    businessId: string
  ): Promise<Uint8Array> {
    if (!this.pdfGenerator) {
      throw new Error('PDF generator not available');
    }

    const businessInfo: BusinessInfo = {
      name: 'Example Business',
      address: '456 Business Ave',
      city: 'Business City',
      state: 'CA',
      zipCode: '54321',
      country: 'US',
      phone: '+1-555-0456',
      email: 'business@example.com',
      website: 'https://example.com'
    };

    return await this.pdfGenerator.generateInvoicePDF(invoice, customer, businessInfo);
  }

  private async generateEmailTemplate(
    invoice: Invoice,
    customer: Customer,
    templateId?: string,
    businessId?: string
  ): Promise<EmailTemplate> {
    const template = await this.getEmailTemplate(templateId || 'default', businessId);
    
    const variables = {
      invoiceNumber: invoice.invoiceNumber,
      customerName: customer.name,
      businessName: 'Example Business',
      totalAmount: formatCurrency(invoice.totalAmount),
      dueDate: formatDate(invoice.dueDate),
      invoiceUrl: `https://app.example.com/invoices/${invoice.id}`
    };

    return {
      subject: this.interpolateTemplate(template.subject, variables),
      htmlBody: this.interpolateTemplate(template.htmlBody, variables),
      textBody: this.interpolateTemplate(template.textBody, variables)
    };
  }

  private async generateReminderTemplate(
    invoice: Invoice,
    customer: Customer,
    businessId: string
  ): Promise<EmailTemplate> {
    const template = await this.getEmailTemplate('reminder', businessId);
    
    const variables = {
      invoiceNumber: invoice.invoiceNumber,
      customerName: customer.name,
      businessName: 'Example Business',
      totalAmount: formatCurrency(invoice.totalAmount),
      dueDate: formatDate(invoice.dueDate),
      daysOverdue: Math.max(0, Math.floor((Date.now() - invoice.dueDate.getTime()) / (1000 * 60 * 60 * 24))),
      invoiceUrl: `https://app.example.com/invoices/${invoice.id}`
    };

    return {
      subject: this.interpolateTemplate(template.subject, variables),
      htmlBody: this.interpolateTemplate(template.htmlBody, variables),
      textBody: this.interpolateTemplate(template.textBody, variables)
    };
  }

  private async generatePaymentConfirmationTemplate(
    invoice: Invoice,
    customer: Customer,
    paymentAmount: number,
    paymentMethod: string,
    businessId: string
  ): Promise<EmailTemplate> {
    const template = await this.getEmailTemplate('payment_confirmation', businessId);
    
    const variables = {
      invoiceNumber: invoice.invoiceNumber,
      customerName: customer.name,
      businessName: 'Example Business',
      paymentAmount: formatCurrency(paymentAmount),
      paymentMethod,
      paymentDate: formatDate(new Date()),
      invoiceUrl: `https://app.example.com/invoices/${invoice.id}`
    };

    return {
      subject: this.interpolateTemplate(template.subject, variables),
      htmlBody: this.interpolateTemplate(template.htmlBody, variables),
      textBody: this.interpolateTemplate(template.textBody, variables)
    };
  }

  private async getEmailTemplate(templateId: string, businessId?: string): Promise<InvoiceTemplate> {
    // This would typically query a database
    // For now, we'll return mock templates
    const templates: Record<string, InvoiceTemplate> = {
      default: {
        id: 'default',
        name: 'Default Invoice Template',
        subject: 'Invoice {{invoiceNumber}} from {{businessName}}',
        htmlBody: this.getDefaultHTMLTemplate(),
        textBody: this.getDefaultTextTemplate(),
        isDefault: true
      },
      reminder: {
        id: 'reminder',
        name: 'Payment Reminder Template',
        subject: 'Payment Reminder - Invoice {{invoiceNumber}}',
        htmlBody: this.getReminderHTMLTemplate(),
        textBody: this.getReminderTextTemplate(),
        isDefault: false
      },
      payment_confirmation: {
        id: 'payment_confirmation',
        name: 'Payment Confirmation Template',
        subject: 'Payment Confirmation - Invoice {{invoiceNumber}}',
        htmlBody: this.getPaymentConfirmationHTMLTemplate(),
        textBody: this.getPaymentConfirmationTextTemplate(),
        isDefault: false
      }
    };

    return templates[templateId] || templates.default;
  }

  private async deliverEmail(email: {
    to: string;
    from: string;
    fromName: string;
    replyTo?: string;
    subject: string;
    htmlBody: string;
    textBody: string;
    attachments?: Array<{
      filename: string;
      content: Uint8Array;
      contentType: string;
    }>;
  }): Promise<EmailDeliveryResult> {
    try {
      // This would typically use an email service like Cloudflare Email
      // For now, we'll simulate the delivery
      const messageId = `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      
      // Simulate delivery delay
      await new Promise(resolve => setTimeout(resolve, 100));

      return {
        messageId,
        status: 'sent',
        deliveredAt: Date.now()
      };
    } catch (error) {
      return {
        messageId: '',
        status: 'failed',
        errorMessage: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  private async updateInvoiceStatus(
    invoiceId: string,
    status: 'sent' | 'failed',
    messageId?: string,
    errorMessage?: string
  ): Promise<void> {
    // This would typically update a database
    this.logger.info('Invoice status updated', {
      invoiceId,
      status,
      messageId,
      errorMessage
    });
  }

  private async updateReminderCount(invoiceId: string): Promise<void> {
    // This would typically update a database
    this.logger.info('Reminder count updated', {
      invoiceId
    });
  }

  private interpolateTemplate(template: string, variables: Record<string, string>): string {
    return template.replace(/\{\{(\w+)\}\}/g, (match, key) => {
      return variables[key] || match;
    });
  }

  private getDefaultHTMLTemplate(): string {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Invoice {{invoiceNumber}}</title>
      </head>
      <body>
        <h1>Invoice {{invoiceNumber}}</h1>
        <p>Dear {{customerName}},</p>
        <p>Thank you for your business! Please find your invoice below:</p>
        <p><strong>Amount Due:</strong> {{totalAmount}}</p>
        <p><strong>Due Date:</strong> {{dueDate}}</p>
        <p><a href="{{invoiceUrl}}">View Invoice Online</a></p>
        <p>Best regards,<br>{{businessName}}</p>
      </body>
      </html>
    `;
  }

  private getDefaultTextTemplate(): string {
    return `
      Invoice {{invoiceNumber}}
      
      Dear {{customerName}},
      
      Thank you for your business! Please find your invoice below:
      
      Amount Due: {{totalAmount}}
      Due Date: {{dueDate}}
      
      View Invoice Online: {{invoiceUrl}}
      
      Best regards,
      {{businessName}}
    `;
  }

  private getReminderHTMLTemplate(): string {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Payment Reminder - Invoice {{invoiceNumber}}</title>
      </head>
      <body>
        <h1>Payment Reminder - Invoice {{invoiceNumber}}</h1>
        <p>Dear {{customerName}},</p>
        <p>This is a friendly reminder that your invoice is {{daysOverdue}} days overdue.</p>
        <p><strong>Amount Due:</strong> {{totalAmount}}</p>
        <p><strong>Due Date:</strong> {{dueDate}}</p>
        <p><a href="{{invoiceUrl}}">Pay Invoice Online</a></p>
        <p>Best regards,<br>{{businessName}}</p>
      </body>
      </html>
    `;
  }

  private getReminderTextTemplate(): string {
    return `
      Payment Reminder - Invoice {{invoiceNumber}}
      
      Dear {{customerName}},
      
      This is a friendly reminder that your invoice is {{daysOverdue}} days overdue.
      
      Amount Due: {{totalAmount}}
      Due Date: {{dueDate}}
      
      Pay Invoice Online: {{invoiceUrl}}
      
      Best regards,
      {{businessName}}
    `;
  }

  private getPaymentConfirmationHTMLTemplate(): string {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Payment Confirmation - Invoice {{invoiceNumber}}</title>
      </head>
      <body>
        <h1>Payment Confirmation - Invoice {{invoiceNumber}}</h1>
        <p>Dear {{customerName}},</p>
        <p>Thank you for your payment! We have received your payment of {{paymentAmount}} via {{paymentMethod}}.</p>
        <p><strong>Payment Date:</strong> {{paymentDate}}</p>
        <p><a href="{{invoiceUrl}}">View Invoice Online</a></p>
        <p>Best regards,<br>{{businessName}}</p>
      </body>
      </html>
    `;
  }

  private getPaymentConfirmationTextTemplate(): string {
    return `
      Payment Confirmation - Invoice {{invoiceNumber}}
      
      Dear {{customerName}},
      
      Thank you for your payment! We have received your payment of {{paymentAmount}} via {{paymentMethod}}.
      
      Payment Date: {{paymentDate}}
      
      View Invoice Online: {{invoiceUrl}}
      
      Best regards,
      {{businessName}}
    `;
  }
}

