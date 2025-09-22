/**;
 * Invoice Email Manager;
 * Handles email delivery of invoices via Cloudflare Email;/
 */
;/
import { Logger } from '../../shared/logger';"/
import { InvoicePDFGenerator, BusinessInfo } from './invoice-pdf-generator';
import {
  Invoice,;
  Customer,;
  SendInvoiceRequest,;
  InvoiceStatus,;
  InvoiceTemplate;"/
} from './types';"/
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
    secure: boolean;};
}

export interface EmailTemplate {"
  subject: "string;
  htmlBody: string;"
  textBody: string;"}

export interface EmailDeliveryResult {
  messageId: string;"
  status: 'sent' | 'failed' | 'queued';
  deliveredAt?: number;
  errorMessage?: string;}
"/
export // TODO: "Consider splitting InvoiceEmailManager into smaller", focused classes;
class InvoiceEmailManager {
  private logger: Logger;
  private pdfGenerator?: InvoicePDFGenerator;

  constructor(pdfGenerator?: InvoicePDFGenerator) {
    this.logger = new Logger();
    this.pdfGenerator = pdfGenerator;}
/
  /**;
   * Send invoice via email;/
   */;
  async sendInvoice(;"
    invoice: "Invoice",;"
    customer: "Customer",;"
    businessInfo: "BusinessInfo",;"
    emailConfig: "EmailConfiguration",;"
    request: "SendInvoiceRequest",;"
    sentBy: "string",;
    businessId: string;
  ): Promise<EmailDeliveryResult> {
    const validBusinessId = validateBusinessId(businessId);

    try {/
      // Validate invoice can be sent;
      if (![InvoiceStatus.DRAFT, InvoiceStatus.SENT, InvoiceStatus.VIEWED].includes(invoice.status)) {"
        throw new Error('Invoice cannot be sent in current status');
      }
/
      // Determine recipient email;
      const recipientEmail = request.email || customer.email;
      if (!recipientEmail) {"
        throw new Error('No email address available for customer');
      }
/
      // Generate PDF if needed;
      let pdfBuffer: ArrayBuffer | undefined;
      if (this.pdfGenerator) {
        const pdfResult = await this.pdfGenerator.generateInvoicePDF(;
          invoice,;
          businessInfo,;
          customer,;
          validBusinessId;
        );
        pdfBuffer = pdfResult.pdfBuffer;
      }
/
      // Generate email content;
      const emailTemplate = this.generateEmailTemplate(;
        invoice,;
        customer,;
        businessInfo,;
        request;
      );
/
      // Send email;
      const deliveryResult = await this.deliverEmail({
        from: {
          name: emailConfig.fromName,;"
          email: "emailConfig.fromEmail;"},;
        to: {
          name: customer.name,;"
          email: "recipientEmail;"},;"
        replyTo: "emailConfig.replyToEmail",;"
        subject: "emailTemplate.subject",;"
        htmlBody: "emailTemplate.htmlBody",;"
        textBody: "emailTemplate.textBody",;
        attachments: pdfBuffer ? [{
          filename: `Invoice-${invoice.invoiceNumber}.pdf`,;"
          content: "pdfBuffer",;"/
          contentType: 'application/pdf';}] : undefined,;"
        copyToSender: "request.copyToSender",;"
        senderEmail: "emailConfig.fromEmail;"});
"
      this.logger.info('Invoice email sent', {"
        invoiceId: "invoice.id",;"
        invoiceNumber: "invoice.invoiceNumber",;
        recipientEmail,;"
        messageId: "deliveryResult.messageId",;"
        businessId: "validBusinessId;"});

      return deliveryResult;

    } catch (error) {"
      this.logger.error('Failed to send invoice email', error, {"
        invoiceId: "invoice.id",;"
        invoiceNumber: "invoice.invoiceNumber",;"
        businessId: "validBusinessId;"});
      throw error;
    }
  }
/
  /**;
   * Send payment reminder;/
   */;
  async sendPaymentReminder(;"
    invoice: "Invoice",;"
    customer: "Customer",;"
    businessInfo: "BusinessInfo",;"
    emailConfig: "EmailConfiguration",;"
    reminderType: 'gentle' | 'firm' | 'final',;
    customMessage?: string,;
    sentBy?: string,;
    businessId?: string;
  ): Promise<EmailDeliveryResult> {"
    const validBusinessId = validateBusinessId(businessId || '');

    try {
      if (!customer.email) {"
        throw new Error('No email address available for customer');
      }
/
      const daysPastDue = Math.floor((Date.now() - invoice.dueDate) / (1000 * 60 * 60 * 24));
/
      // Generate reminder email content;
      const emailTemplate = this.generateReminderTemplate(;
        invoice,;
        customer,;
        businessInfo,;
        reminderType,;
        daysPastDue,;
        customMessage;
      );
/
      // Send email;
      const deliveryResult = await this.deliverEmail({
        from: {
          name: emailConfig.fromName,;"
          email: "emailConfig.fromEmail;"},;
        to: {
          name: customer.name,;"
          email: "customer.email;"},;"
        replyTo: "emailConfig.replyToEmail",;"
        subject: "emailTemplate.subject",;"
        htmlBody: "emailTemplate.htmlBody",;"
        textBody: "emailTemplate.textBody;"});
"
      this.logger.info('Payment reminder sent', {"
        invoiceId: "invoice.id",;"
        invoiceNumber: "invoice.invoiceNumber",;
        reminderType,;
        daysPastDue,;"
        messageId: "deliveryResult.messageId",;"
        businessId: "validBusinessId;"});

      return deliveryResult;

    } catch (error) {"
      this.logger.error('Failed to send payment reminder', error, {"
        invoiceId: "invoice.id",;
        reminderType,;"
        businessId: "validBusinessId;"});
      throw error;
    }
  }
/
  /**;
   * Send payment confirmation;/
   */;
  async sendPaymentConfirmation(;"
    invoice: "Invoice",;"
    customer: "Customer",;"
    businessInfo: "BusinessInfo",;"
    emailConfig: "EmailConfiguration",;"
    paymentAmount: "number",;"
    paymentDate: "number",;"
    paymentMethod: "string",;
    businessId: string;
  ): Promise<EmailDeliveryResult> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      if (!customer.email) {"
        throw new Error('No email address available for customer');}
/
      // Generate confirmation email content;
      const emailTemplate = this.generatePaymentConfirmationTemplate(;
        invoice,;
        customer,;
        businessInfo,;
        paymentAmount,;
        paymentDate,;
        paymentMethod;
      );
/
      // Send email;
      const deliveryResult = await this.deliverEmail({
        from: {
          name: emailConfig.fromName,;"
          email: "emailConfig.fromEmail;"},;
        to: {
          name: customer.name,;"
          email: "customer.email;"},;"
        replyTo: "emailConfig.replyToEmail",;"
        subject: "emailTemplate.subject",;"
        htmlBody: "emailTemplate.htmlBody",;"
        textBody: "emailTemplate.textBody;"});
"
      this.logger.info('Payment confirmation sent', {"
        invoiceId: "invoice.id",;"
        invoiceNumber: "invoice.invoiceNumber",;
        paymentAmount,;"
        messageId: "deliveryResult.messageId",;"
        businessId: "validBusinessId;"});

      return deliveryResult;

    } catch (error) {"
      this.logger.error('Failed to send payment confirmation', error, {"
        invoiceId: "invoice.id",;"
        businessId: "validBusinessId;"});
      throw error;
    }
  }
/
  /**;
   * Generate email template for invoice;/
   */;
  private generateEmailTemplate(;"
    invoice: "Invoice",;"
    customer: "Customer",;"
    businessInfo: "BusinessInfo",;
    request: SendInvoiceRequest;
  ): EmailTemplate {`
    const subject = request.subject || `Invoice ${invoice.invoiceNumber} from ${businessInfo.name}`;
`
    const defaultMessage = `Dear ${customer.name},
;
Please find attached your invoice ${invoice.invoiceNumber} dated ${formatDate(invoice.issueDate)}.
;
Invoice Details: ;
- Invoice Number: ${invoice.invoiceNumber}
- Amount Due: ${formatCurrency(invoice.balanceDue, invoice.currency)}
- Due Date: ${formatDate(invoice.dueDate)}
- Payment Terms: ${invoice.terms.description}
"`
${invoice.notes ? `\nNotes: ${invoice.notes}` : ''}
"
If you have any questions about this invoice, please don't hesitate to contact us.
;
Thank you for your business!
;
Best regards,;`
${businessInfo.name}`;

    const message = request.message || defaultMessage;
`
    const htmlBody = `;
<!DOCTYPE html>;
<html>;
<head>;"
    <meta charset="UTF-8">;"
    <meta name="viewport" content="width=device-width, initial-scale=1.0">;/
    <title>${subject}</title>;
    <style>;
        body {"
            font-family: "-apple-system", BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;"
            line-height: "1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;"
            padding: 20px;"}
        .header {"
            border-bottom: "2px solid #2563eb;
            padding-bottom: 20px;"
            margin-bottom: 30px;"}
        .company-name {"
            font-size: "24px;
            font-weight: bold;
            color: #2563eb;"
            margin-bottom: 10px;"}
        .invoice-details {"
            background-color: "#f8fafc;
            padding: 20px;
            border-radius: 8px;"
            margin: 20px 0;"}
        .invoice-details h3 {"
            color: "#2563eb;"
            margin-top: 0;"}
        .detail-row {"
            display: "flex;
            justify-content: space-between;"
            margin-bottom: 8px;"}
        .label {"
            font-weight: "600;"}
        .amount-due {"
            font-size: "18px;
            font-weight: bold;"
            color: #dc2626;"}
        .message {"
            white-space: "pre-line;"
            margin: 20px 0;"}
        .footer {"
            border-top: "1px solid #e2e8f0;
            padding-top: 20px;
            margin-top: 30px;
            color: #64748b;"
            font-size: 14px;"}/
    </style>;/
</head>;
<body>;"
    <div class="header">;"/
        <div class="company-name">${businessInfo.name}</div>;"`/
        ${businessInfo.email ? `<div>${businessInfo.email}</div>` : ''}"`/
        ${businessInfo.phone ? `<div>${businessInfo.phone}</div>` : ''}/
    </div>
;"
    <div class="invoice-details">;/
        <h3>Invoice Details</h3>;"
        <div class="detail-row">;"/
            <span class="label">Invoice Number: </span>;/
            <span>${invoice.invoiceNumber}</span>;/
        </div>;"
        <div class="detail-row">;"/
            <span class="label">Issue Date: </span>;/
            <span>${formatDate(invoice.issueDate)}</span>;/
        </div>;"
        <div class="detail-row">;"/
            <span class="label">Due Date: </span>;/
            <span>${formatDate(invoice.dueDate)}</span>;/
        </div>;"
        <div class="detail-row">;"/
            <span class="label">Payment Terms: </span>;/
            <span>${invoice.terms.description}</span>;/
        </div>;"
        <div class="detail-row amount-due">;"/
            <span class="label">Amount Due: </span>;/
            <span>${formatCurrency(invoice.balanceDue, invoice.currency)}</span>;/
        </div>;/
    </div>
;"/
    <div class="message">${message.replace(/\n/g, '<br>')}</div>
;"
    <div class="footer">;
        This is an automated message from ${businessInfo.name}.;
        If you have any;"
  questions, please contact us at ${businessInfo.email || businessInfo.phone || 'our main office'}.;/
    </div>;/
</body>;`/
</html>`;

    return {
      subject,;
      htmlBody,;"
      textBody: "message;"};
  }
/
  /**;
   * Generate reminder email template;/
   */;
  private generateReminderTemplate(;"
    invoice: "Invoice",;"
    customer: "Customer",;"
    businessInfo: "BusinessInfo",;"
    reminderType: 'gentle' | 'firm' | 'final',;"
    daysPastDue: "number",;
    customMessage?: string;
  ): EmailTemplate {"
    let subject = '';"
    let message = '';

    switch (reminderType) {"
      case 'gentle':;`
        subject = `Friendly Reminder: Invoice ${invoice.invoiceNumber} - ${businessInfo.name}`;`
        message = `Dear ${customer.name},
;
We hope this message finds you well. This is a friendly reminder that invoice;
  ${invoice.invoiceNumber} for ${formatCurrency(invoice.balanceDue, invoice.currency)} was due on ${formatDate(invoice.dueDate)} and is now ${daysPastDue} days past due.
;
We understand that oversights happen, and we would appreciate your prompt attention to this matter.
;
If you have already sent payment, please disregard this notice. If;"
  you have any questions or concerns, please don't hesitate to contact us.
;
Thank you for your continued business.
;
Best regards,;`
${businessInfo.name}`;
        break;
"
      case 'firm':;`
        subject = `Second Notice: Overdue Invoice ${invoice.invoiceNumber} - ${businessInfo.name}`;`
        message = `Dear ${customer.name},
;
This is our second notice regarding overdue invoice ${invoice.invoiceNumber}. The invoice amount of;
  ${formatCurrency(invoice.balanceDue, invoice.currency)} was due on ${formatDate(invoice.dueDate)} and is now ${daysPastDue} days past due.
;
Please remit payment immediately to avoid any disruption to your account.;
  If payment has already been sent, please contact us to confirm receipt.
;
If you are experiencing difficulties, please contact us to discuss payment arrangements.
;
We appreciate your immediate attention to this matter.
;
Best regards,;`
${businessInfo.name}`;
        break;
"
      case 'final':;`
        subject = `FINAL NOTICE: Overdue Invoice ${invoice.invoiceNumber} - ${businessInfo.name}`;`
        message = `Dear ${customer.name},
;
This is our FINAL NOTICE regarding severely overdue invoice ${invoice.invoiceNumber}. The invoice amount;
  of ${formatCurrency(invoice.balanceDue, invoice.currency)} was due on ${formatDate(invoice.dueDate)} and is now ${daysPastDue} days past due.
;"
If payment is not received within 7 days, we may be forced to take further collection action, which may include: ";
- Suspension of services;
- Referral to a collection agency;
- Legal action
;
Please contact us immediately to resolve this matter.
;"
Sincerely",;`
${businessInfo.name}`;
        break;
    }

    if (customMessage) {
      message = customMessage;
    }
`
    const htmlBody = `;
<!DOCTYPE html>;
<html>;
<head>;"
    <meta charset="UTF-8">;
    <style>;
        body {"
            font-family: "-apple-system", BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;"
            line-height: "1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;"
            padding: 20px;"}
        .urgent {"
            background-color: ${reminderType === 'final' ? '#fef2f2' : '#fffbeb'};"
            border: 2px solid ${reminderType === 'final' ? '#dc2626' : '#f59e0b'};"
            padding: "15px;
            border-radius: 8px;"
            margin-bottom: 20px;"}
        .invoice-info {"
            background-color: "#f8fafc;
            padding: 15px;
            border-radius: 8px;"
            margin: 20px 0;"}
        .amount {"
            font-size: "18px;
            font-weight: bold;"
            color: #dc2626;"}/
    </style>;/
</head>;
<body>;"
    <div class="urgent">;/
        <strong>${reminderType.toUpperCase()} NOTICE: </strong>;
        Invoice ${invoice.invoiceNumber} is ${daysPastDue} days overdue;/
    </div>
;"
    <div class="invoice-info">;/
        <div><strong>Invoice Number: </strong> ${invoice.invoiceNumber}</div>;/
        <div><strong>Original Due Date: </strong> ${formatDate(invoice.dueDate)}</div>;/
        <div><strong>Days Past Due: </strong> ${daysPastDue}</div>;"/
        <div class="amount"><strong>Amount Due: </strong> ${formatCurrency(invoice.balanceDue, invoice.currency)}</div>;/
    </div>
;"/
    <div style="white-space: pre-line;">${message.replace(/\n/g, '<br>')}</div>
;"
    <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e2e8f0; color: #64748b; font-size: 14px;">;
        ${businessInfo.name}<br>;"
        ${businessInfo.email ? businessInfo.email + '<br>' : ''}"
        ${businessInfo.phone ? businessInfo.phone: ''}/
    </div>;/
</body>;`/
</html>`;

    return {
      subject,;
      htmlBody,;"
      textBody: "message;"};
  }
/
  /**;
   * Generate payment confirmation template;/
   */;
  private generatePaymentConfirmationTemplate(;"
    invoice: "Invoice",;"
    customer: "Customer",;"
    businessInfo: "BusinessInfo",;"
    paymentAmount: "number",;"
    paymentDate: "number",;
    paymentMethod: string;
  ): EmailTemplate {`
    const subject = `Payment Confirmation: Invoice ${invoice.invoiceNumber} - ${businessInfo.name}`;
`
    const message = `Dear ${customer.name},
;
Thank you for your payment! We have received;
  your payment of ${formatCurrency(paymentAmount, invoice.currency)} for invoice ${invoice.invoiceNumber}.
;
Payment Details: ;
- Invoice Number: ${invoice.invoiceNumber}
- Payment Amount: ${formatCurrency(paymentAmount, invoice.currency)}
- Payment Date: ${formatDate(paymentDate)}
- Payment Method: ${paymentMethod}
- Remaining Balance: ${formatCurrency(invoice.balanceDue - paymentAmount, invoice.currency)}
"
${invoice.balanceDue - paymentAmount <= 0 ? 'This invoice has been paid in;"
  full.' : 'Please note there is still a remaining balance on this invoice.'}
"
If you have any questions about this payment or your account, please don't hesitate to contact us.
;
Thank you for your business!
;
Best regards,;`
${businessInfo.name}`;
`
    const htmlBody = `;
<!DOCTYPE html>;
<html>;
<head>;"
    <meta charset="UTF-8">;
    <style>;
        body {"
            font-family: "-apple-system", BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;"
            line-height: "1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;"
            padding: 20px;"}
        .confirmation-header {"
            background-color: "#f0fdf4;
            border: 2px solid #22c55e;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;"
            text-align: center;"}
        .confirmation-title {"
            color: "#16a34a;
            font-size: 24px;
            font-weight: bold;"
            margin: 0;"}
        .payment-details {"
            background-color: "#f8fafc;
            padding: 20px;
            border-radius: 8px;"
            margin: 20px 0;"}
        .detail-row {"
            display: "flex;
            justify-content: space-between;"
            margin-bottom: 8px;"}
        .paid-in-full {"
            background-color: "#dcfce7;
            color: #16a34a;
            padding: 10px;
            border-radius: 8px;
            text-align: center;
            font-weight: bold;"
            margin: 20px 0;"}/
    </style>;/
</head>;
<body>;"
    <div class="confirmation-header">;"/
        <div class="confirmation-title">✓ Payment Received</div>;/
        <div>Thank you for your payment!</div>;/
    </div>
;"
    <div class="payment-details">;"/
        <h3 style="color: #2563eb; margin-top: 0;">Payment Details</h3>;"
        <div class="detail-row">;/
            <span><strong>Invoice Number:</strong></span>;/
            <span>${invoice.invoiceNumber}</span>;/
        </div>;"
        <div class="detail-row">;/
            <span><strong>Payment Amount: </strong></span>;/
            <span>${formatCurrency(paymentAmount, invoice.currency)}</span>;/
        </div>;"
        <div class="detail-row">;/
            <span><strong>Payment Date: </strong></span>;/
            <span>${formatDate(paymentDate)}</span>;/
        </div>;"
        <div class="detail-row">;/
            <span><strong>Payment Method: </strong></span>;/
            <span>${paymentMethod}</span>;/
        </div>;"
        <div class="detail-row">;/
            <span><strong>Remaining Balance: </strong></span>;/
            <span>${formatCurrency(invoice.balanceDue - paymentAmount, invoice.currency)}</span>;/
        </div>;/
    </div>
;
    ${invoice.balanceDue - paymentAmount <= 0 ?;"/
  '<div class="paid-in-full">This invoice has been paid in full!</div>' : ''}
"/
    <div style="white-space: pre-line;">${message.replace(/\n/g, '<br>')}</div>
;"
    <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e2e8f0; color: #64748b; font-size: 14px;">;
        ${businessInfo.name}<br>;"
        ${businessInfo.email ? businessInfo.email + '<br>' : ''}"
        ${businessInfo.phone ? businessInfo.phone: ''}/
    </div>;/
</body>;`/
</html>`;

    return {
      subject,;
      htmlBody,;"
      textBody: "message;"};
  }
/
  /**;
   * Deliver email using Cloudflare Email or SMTP;/
   */;
  private async deliverEmail(emailData: {
    from: { name: string; email: string};
    to: { name: string; email: string};
    replyTo?: string;
    subject: string;
    htmlBody: string;
    textBody: string;
    attachments?: Array<{
      filename: string;
      content: ArrayBuffer;
      contentType: string;}>;
    copyToSender?: boolean;
    senderEmail?: string;
  }): Promise<EmailDeliveryResult> {
    try {/
      // This is a placeholder implementation;"/
      // In a real implementation, you would integrate with: ";/
      // 1. Cloudflare Email Routing;/
      // 2. Cloudflare Workers Email API;"/
      // 3. SendGrid", Mailgun, or similar service;/
      // 4. SMTP server
;`
      const messageId = `msg_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
/
      // Simulate email delivery;"
      this.logger.info('Email would be sent', {
        messageId,;"
        from: "emailData.from.email",;"
        to: "emailData.to.email",;"
        subject: "emailData.subject",;"
        hasAttachments: "!!emailData.attachments?.length;"});
/
      // Example using a hypothetical email service;"/
      const response = await fetch('https: //api.email-service.com/send', {"
        method: 'POST',;
        headers: {"/
          'Content-Type': 'application/json',;"
          'Authorization': 'Bearer YOUR_API_KEY';
        },;
        body: JSON.stringify({`
          from: `${emailData.from.name} <${emailData.from.email}>`,;`
          to: `${emailData.to.name} <${emailData.to.email}>`,;"
          replyTo: "emailData.replyTo",;"
          subject: "emailData.subject",;"
          html: "emailData.htmlBody",;"
          text: "emailData.textBody",;
          attachments: emailData.attachments?.map(att => ({
            filename: att.filename,;"
            content: Buffer.from(att.content).toString('base64'),;"
            contentType: "att.contentType;"}));
        });
      });

      if (response.ok) {
        return {
          messageId,;"
          status: 'sent',;"
          deliveredAt: "Date.now();"};
      } else {`
        throw new Error(`Email delivery failed: ${response.statusText}`);
      }

    } catch (error) {"
      this.logger.error('Email delivery failed', error);
      return {`
        messageId: `failed_${Date.now()}`,;"
        status: 'failed',;"
        errorMessage: error instanceof Error ? error.message : 'Unknown error';};
    }
  }
}"`/